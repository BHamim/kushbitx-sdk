// Offline tests: a throwaway in-memory key (never funded) and a mocked KushBitx server. Nothing is broadcast.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { kushbitxActionProvider, paymentPolicy, PAY_TO, USDC_BASE, BASE_NETWORK } from '../index.mjs';

// No real network in tests: AgentKit's own analytics calls are blocked here; the provider uses the injected fetch.
globalThis.fetch = async () => new Response(null, { status: 204 }); // swallowed, never sent
const account = privateKeyToAccount(generatePrivateKey());
const wallet = (chainId = 8453) => ({
  getName: () => 'test_wallet', toSigner: () => account, getAddress: () => account.address,
  getNetwork: () => ({ protocolFamily: 'evm', networkId: chainId === 8453 ? 'base-mainnet' : 'base-sepolia', chainId: String(chainId) }),
  readContract: async () => 0n
});
const requirement = (amount = '980', payTo = PAY_TO) => ({ scheme: 'exact', network: BASE_NETWORK, amount, asset: USDC_BASE, payTo, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } });

function server({ amount = '980', payTo = PAY_TO } = {}) {
  const seen = [];
  const fetch = async (input, init = {}) => {
    // The x402 wrapper passes a Request; our provider passes (url, init). Read both.
    const req = input instanceof Request ? input : new Request(input, init);
    const url = req.url, headers = req.headers, body = req.method === 'POST' ? await req.text() : undefined;
    seen.push({ url, method: req.method, channel: headers.get('x-kushbitx-channel'), ua: headers.get('user-agent'), signature: headers.get('PAYMENT-SIGNATURE'), body });
    if (String(url).endsWith('/api/spendguard/evaluate')) return new Response(JSON.stringify({ decision: 'APPROVE', advisory: true }), { status: 200 });
    if (!headers.get('PAYMENT-SIGNATURE')) {
      const required = { x402Version: 2, error: 'Payment required', resource: { url: String(url), description: 'x', mimeType: 'application/json' }, accepts: [requirement(amount, payTo)] };
      return new Response(JSON.stringify(required), { status: 402, headers: { 'PAYMENT-REQUIRED': btoa(JSON.stringify(required)) } });
    }
    return new Response(JSON.stringify({ status: 'PASS', receipt: { reportId: 'r1' } }), { status: 200 });
  };
  return { fetch, seen };
}

const actions = (opts, w = wallet()) => Object.fromEntries(kushbitxActionProvider(opts).getActions(w).map(a => [a.name.replace(/^.*?_kushbitx/, 'kushbitx'), a]));

test('five actions with KushBitx names', () => {
  const names = Object.keys(actions({ fetch: server().fetch })).sort();
  assert.deepEqual(names, ['kushbitx_quick_check', 'kushbitx_spendguard_evaluate', 'kushbitx_token_risk', 'kushbitx_transaction_preflight', 'kushbitx_verify_payment']);
});

test('free SpendGuard: no payment, agentkit channel header, chain and asset filled', async () => {
  const s = server();
  const out = JSON.parse(await actions({ fetch: s.fetch }).kushbitx_spendguard_evaluate.invoke({
    agentId: 'a', requestId: 'r', recipient: PAY_TO, amount: '5.00',
    policy: { maxPerTransaction: '10', remainingDailyBudget: '50', requireHumanAbove: '25', maxRepeats: 3, allowedRecipients: [PAY_TO], blockUnknownRecipients: true }
  }));
  assert.equal(out.decision, 'APPROVE');
  assert.equal(s.seen.length, 1);
  assert.equal(s.seen[0].channel, 'agentkit');
  assert.match(s.seen[0].ua, /^kushbitx-agentkit\//);
  assert.equal(s.seen[0].signature, null);
  const body = JSON.parse(s.seen[0].body);
  assert.equal(body.chain, 'base');
  assert.equal(body.asset, 'USDC');
});

test('paid token risk: one signed retry for exactly 980 to PAY_TO', async () => {
  const s = server();
  const out = JSON.parse(await actions({ fetch: s.fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(out.status, 'PASS');
  assert.equal(s.seen.length, 2);
  const payload = JSON.parse(atob(s.seen[1].signature));
  assert.equal(payload.payload.authorization.value, '980');
  assert.equal(payload.payload.authorization.to.toLowerCase(), PAY_TO.toLowerCase());
  assert.equal(s.seen[1].channel, 'agentkit');
});

test('price above the cap: refused before signing', async () => {
  const s = server({ amount: '20000' });
  const out = JSON.parse(await actions({ fetch: s.fetch, maxPaymentUsdc: '0.01' }).kushbitx_quick_check.invoke({}));
  assert.equal(out.error, true);
  assert.ok(s.seen.every(r => !r.signature));
});

test('different recipient: refused before signing', async () => {
  const s = server({ payTo: '0x' + '9'.repeat(40) });
  const out = JSON.parse(await actions({ fetch: s.fetch }).kushbitx_quick_check.invoke({}));
  assert.equal(out.error, true);
  assert.ok(s.seen.every(r => !r.signature));
});

test('wallet not on Base mainnet: refused without any request', async () => {
  const s = server();
  const out = JSON.parse(await actions({ fetch: s.fetch }, wallet(84532)).kushbitx_quick_check.invoke({}));
  assert.equal(out.error, true);
  assert.equal(s.seen.length, 0);
});

test('policy keeps only Base USDC to PAY_TO within the cap', () => {
  const keep = paymentPolicy(10000n)(2, [requirement('980'), requirement('20000'), requirement('980', '0x' + '9'.repeat(40)), { ...requirement('980'), network: 'eip155:84532' }]);
  assert.deepEqual(keep.map(r => r.amount), ['980']);
});

test('origin must be KushBitx', () => {
  assert.throws(() => kushbitxActionProvider({ origin: 'https://evil.example' }), /origin must be/);
});
