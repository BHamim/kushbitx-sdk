// Offline tests: a throwaway in-memory key (never funded) and a mocked KushBitx server. Nothing is broadcast.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { kushbitxActionProvider, paymentPolicy, preflightDigest, PAY_TO, USDC_BASE, BASE_NETWORK } from '../index.mjs';

// No real network in tests: AgentKit's own analytics calls are blocked here; the provider uses the injected fetch.
globalThis.fetch = async () => new Response(null, { status: 204 }); // swallowed, never sent
const account = privateKeyToAccount(generatePrivateKey());
const wallet = (chainId = 8453) => ({
  getName: () => 'test_wallet', toSigner: () => account, getAddress: () => account.address,
  getNetwork: () => ({ protocolFamily: 'evm', networkId: chainId === 8453 ? 'base-mainnet' : 'base-sepolia', chainId: String(chainId) }),
  readContract: async () => 0n
});
const requirement = (amount = '1000', payTo = PAY_TO) => ({ scheme: 'exact', network: BASE_NETWORK, amount, asset: USDC_BASE, payTo, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } });

function server({ amount = '1000', payTo = PAY_TO, report = null, paidStatus = 200, ordersDown = false, throwAfterSign = false, badJson = false, freeBadJson = false } = {}) {
  const seen = [];
  const fetch = async (input, init = {}) => {
    // The x402 wrapper passes a Request; our provider passes (url, init). Read both.
    const req = input instanceof Request ? input : new Request(input, init);
    const url = req.url, headers = req.headers, body = req.method === 'POST' ? await req.text() : undefined;
    seen.push({ url, method: req.method, channel: headers.get('x-kushbitx-channel'), ua: headers.get('user-agent'), signature: headers.get('PAYMENT-SIGNATURE'), body });
    if (String(url).endsWith('/api/orders/recover')) return new Response(JSON.stringify({ status: 'complete', restored: JSON.parse(body) }), { status: 200 });
    if (freeBadJson && String(url).endsWith('/api/spendguard/evaluate')) return new Response('<html>oops', { status: 200 });
    if (String(url).endsWith('/api/spendguard/evaluate')) return new Response(JSON.stringify({ decision: 'APPROVE', advisory: true }), { status: 200 });
    if (String(url).endsWith('/api/orders')) return ordersDown ? new Response('{}', { status: 503 }) : new Response(JSON.stringify({ id: 'rid-1', key: 'rkey-1', expiresAt: '2026-11-01T00:00:00Z' }), { status: 201 });
    if (!headers.get('PAYMENT-SIGNATURE')) {
      const required = { x402Version: 2, error: 'Payment required', resource: { url: String(url), description: 'x', mimeType: 'application/json' }, accepts: [requirement(amount, payTo)] };
      return new Response(JSON.stringify(required), { status: 402, headers: { 'PAYMENT-REQUIRED': btoa(JSON.stringify(required)) } });
    }
    if (throwAfterSign) throw new TypeError('fetch failed');
    if (badJson) return new Response('not json', { status: 200 });
    if (paidStatus !== 200) return new Response(JSON.stringify({ error: 'Upstream provider unavailable' }), { status: paidStatus });
    return new Response(JSON.stringify(report ? report(JSON.parse(body || '{}')) : { status: 'PASS', receipt: { reportId: 'r1' } }), { status: 200 });
  };
  return { fetch, seen };
}

const actions = (opts, w = wallet()) => Object.fromEntries(kushbitxActionProvider(opts).getActions(w).map(a => [a.name.replace(/^.*?_kushbitx/, 'kushbitx'), a]));

test('seven actions with KushBitx names (0.1.3 adds the free restore action)', () => {
  const names = Object.keys(actions({ fetch: server().fetch })).sort();
  assert.deepEqual(names, ['kushbitx_preflight_transaction', 'kushbitx_quick_check', 'kushbitx_restore_report', 'kushbitx_spendguard_evaluate', 'kushbitx_token_risk', 'kushbitx_transaction_preflight', 'kushbitx_verify_payment']);
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

test('paid token risk: one signed retry for exactly 1000 to PAY_TO', async () => {
  const s = server();
  const out = JSON.parse(await actions({ fetch: s.fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(out.status, 'PASS');
  // 0.1.2: recovery is prepared first (POST /api/orders), then the 402 probe, then one signed retry.
  assert.equal(s.seen.length, 3);
  assert.ok(s.seen[0].url.endsWith('/api/orders') && !s.seen[0].signature);
  const payload = JSON.parse(atob(s.seen[2].signature));
  assert.equal(payload.payload.authorization.value, '1000');
  assert.equal(payload.payload.authorization.to.toLowerCase(), PAY_TO.toLowerCase());
  assert.equal(s.seen[2].channel, 'agentkit');
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
  const keep = paymentPolicy(10000n)(2, [requirement('1000'), requirement('20000'), requirement('1000', '0x' + '9'.repeat(40)), { ...requirement('1000'), network: 'eip155:84532' }]);
  assert.deepEqual(keep.map(r => r.amount), ['1000']);
});

test('origin must be KushBitx', () => {
  assert.throws(() => kushbitxActionProvider({ origin: 'https://evil.example' }), /origin must be/);
});

test('Preflight 1.1: canSign only for ALLOW on the same digest before expiresAt', async () => {
  const tx = { chainId: 8453, from: PAY_TO, to: USDC_BASE, value: '0', data: '0xa9059cbb' + '0'.repeat(128), intent: 'transfer' };
  const later = new Date(Date.now() + 60000).toISOString();
  const run = async report => JSON.parse(await actions({ fetch: server({ amount: '5000', report }).fetch }).kushbitx_preflight_transaction.invoke(tx));
  const ok = await run(input => ({ verdict: 'ALLOW', transactionDigest: preflightDigest(input), expiresAt: later }));
  assert.equal(ok.canSign, true);
  assert.equal((await run(() => ({ verdict: 'ALLOW', transactionDigest: '0x' + '0'.repeat(64), expiresAt: later }))).canSign, false);
  assert.equal((await run(input => ({ verdict: 'REVIEW', transactionDigest: preflightDigest(input), expiresAt: later }))).canSign, false);
  assert.equal((await run(input => ({ verdict: 'ALLOW', transactionDigest: preflightDigest(input), expiresAt: new Date(Date.now() - 1).toISOString() }))).canSign, false);
});

test('0.1.2: recovery is prepared before signing; "not paid" only when nothing was signed, otherwise "unknown" with restore steps', async () => {
  const noRecovery = JSON.parse(await actions({ fetch: server({ ordersDown: true }).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(noRecovery.paymentStatus, 'not_paid');
  const capped = server({ amount: '20000' });
  const refused = JSON.parse(await actions({ fetch: capped.fetch, maxPaymentUsdc: '0.01' }).kushbitx_quick_check.invoke({}));
  assert.equal(refused.paymentStatus, 'not_paid');
  assert.ok(capped.seen.every(r => !r.signature));
  const upstream = JSON.parse(await actions({ fetch: server({ paidStatus: 502 }).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(upstream.paymentStatus, 'unknown');
  assert.doesNotMatch(upstream.message, /not made/i);
  assert.equal(upstream.recovery.reportId, 'rid-1');
  assert.equal(upstream.recovery.restoreWith, 'kushbitx_restore_report');
  const dropped = JSON.parse(await actions({ fetch: server({ throwAfterSign: true }).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(dropped.paymentStatus, 'unknown');
  assert.equal(dropped.recovery.restoreWith, 'kushbitx_restore_report');
  const rejected = JSON.parse(await actions({ fetch: server({ paidStatus: 402 }).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(rejected.paymentStatus, 'not_paid');
});

test('0.1.2: canSign is false for another chainId or a report for another chain', async () => {
  const later = new Date(Date.now() + 60000).toISOString();
  const tx = { chainId: 8453, from: PAY_TO, to: USDC_BASE, value: '0', data: '0x', intent: 'transfer' };
  const run = async report => JSON.parse(await actions({ fetch: server({ amount: '5000', report }).fetch }).kushbitx_preflight_transaction.invoke(tx));
  assert.equal((await run(input => ({ verdict: 'ALLOW', chainId: 8453, transactionDigest: preflightDigest(input), expiresAt: later }))).canSign, true);
  assert.equal((await run(input => ({ verdict: 'ALLOW', chainId: 1, transactionDigest: preflightDigest(input), expiresAt: later }))).canSign, false);
  assert.notEqual(preflightDigest({ ...tx, chainId: 1 }), preflightDigest(tx));
});

test('0.1.2: a server report cannot override the locally computed canSign or digestMatches', async () => {
  const later = new Date(Date.now() + 60000).toISOString();
  const tx = { chainId: 8453, from: PAY_TO, to: USDC_BASE, value: '0', data: '0x', intent: 'transfer' };
  const run = async report => JSON.parse(await actions({ fetch: server({ amount: '5000', report }).fetch }).kushbitx_preflight_transaction.invoke(tx));
  // A REVIEW report that claims canSign and digestMatches.
  const forged = await run(() => ({ verdict: 'REVIEW', canSign: true, digestMatches: true, transactionDigest: '0x' + '0'.repeat(64), expiresAt: later }));
  assert.equal(forged.canSign, false);
  assert.equal(forged.digestMatches, false);
  assert.deepEqual(forged.server, { canSign: true, digestMatches: true });
  // An ALLOW report with a wrong digest that claims canSign.
  const wrongDigest = await run(() => ({ verdict: 'ALLOW', canSign: true, transactionDigest: '0x' + '1'.repeat(64), expiresAt: later }));
  assert.equal(wrongDigest.canSign, false);
  // A genuine ALLOW that claims canSign false still gets the local answer.
  const genuine = await run(input => ({ verdict: 'ALLOW', canSign: false, chainId: 8453, transactionDigest: preflightDigest(input), expiresAt: later }));
  assert.equal(genuine.canSign, true);
  assert.equal(genuine.server.canSign, false);
  // Keys order: the local fields come last, so no later spread can replace them.
  const keys = Object.keys(forged);
  assert.deepEqual(keys.slice(-2), ['canSign', 'digestMatches']);
});

test('0.1.2: a missing chainId never signs', async () => {
  const later = new Date(Date.now() + 60000).toISOString();
  const { kushbitxActionProvider: provider } = await import('../index.mjs');
  const tx = { from: PAY_TO, to: USDC_BASE, value: '0', data: '0x' };
  const action = provider({ fetch: server({ amount: '5000', report: input => ({ verdict: 'ALLOW', transactionDigest: preflightDigest({ ...input, chainId: 8453 }), expiresAt: later }) }).fetch }).getActions(wallet()).find(a => a.name.endsWith('kushbitx_preflight_transaction'));
  // chainId has no default in the schema: AgentKit refuses the call, and a direct call never signs.
  let out = null;
  try { out = JSON.parse(await action.invoke(tx)); } catch { out = null; }
  assert.ok(out === null || out.canSign === false, JSON.stringify(out));
  assert.equal(action.schema.safeParse(tx).success, false, 'the schema requires chainId');
});

const SERVICES = [
  ['kushbitx_preflight_transaction', { chainId: 8453, from: PAY_TO, to: USDC_BASE, value: '0', data: '0x' }],
  ['kushbitx_quick_check', {}],
  ['kushbitx_token_risk', { address: USDC_BASE }],
  ['kushbitx_transaction_preflight', { to: USDC_BASE }],
  ['kushbitx_verify_payment', { txHash: '0x' + 'a'.repeat(64), expectedTo: PAY_TO, expectedAmount: '1.00' }]
];

test('0.1.3 R01: maxPaymentUsdc=0.001 refuses a 5000-unit price for every paid action, Preflight included', async () => {
  for (const [name, args] of SERVICES) {
    const s = server({ amount: '5000' });
    const out = JSON.parse(await actions({ fetch: s.fetch, maxPaymentUsdc: '0.001' })[name].invoke(args));
    assert.equal(out.error, true, name);
    assert.equal(out.paymentStatus, 'not_paid', name);
    assert.ok(s.seen.every(r => !r.signature), name + ' must not sign');
  }
  // The lower cap wins either way; the defaults still pay Preflight's 0.005.
  const low = server({ amount: '5000' });
  assert.equal(JSON.parse(await actions({ fetch: low.fetch, maxPreflightUsdc: '0.001' }).kushbitx_preflight_transaction.invoke(SERVICES[0][1])).paymentStatus, 'not_paid');
  const ok = server({ amount: '5000', report: () => ({ verdict: 'REVIEW' }) });
  assert.equal(JSON.parse(await actions({ fetch: ok.fetch }).kushbitx_preflight_transaction.invoke(SERVICES[0][1])).verdict, 'REVIEW');
});

test('0.1.3 R02: the recovery key never appears in any action output', async () => {
  for (const opts of [{ paidStatus: 502 }, { throwAfterSign: true }, { badJson: true }, { paidStatus: 402 }, { ordersDown: true }, {}]) {
    const text = await actions({ fetch: server(opts).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE });
    assert.doesNotMatch(text, /rkey-1/, JSON.stringify(opts));
  }
});

test('0.1.3 R02: kushbitx_restore_report restores with the stored key; without one it refuses and never pays', async () => {
  const s = server({ paidStatus: 502 });
  const a = actions({ fetch: s.fetch });
  const first = JSON.parse(await a.kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(first.paymentStatus, 'unknown');
  const restored = JSON.parse(await a.kushbitx_restore_report.invoke({ reportId: first.recovery.reportId }));
  // The mock echoes the request body: the stored key was sent to /api/orders/recover.
  assert.deepEqual(restored.restored, { id: 'rid-1', key: 'rkey-1' });
  const missing = JSON.parse(await actions({ fetch: server().fetch }).kushbitx_restore_report.invoke({ reportId: 'rid-unknown' }));
  assert.equal(missing.error, true);
  const fromHost = actions({ fetch: server().fetch, getRecoveryKey: id => id === 'rid-9' ? 'hostkey' : null });
  assert.deepEqual(JSON.parse(await fromHost.kushbitx_restore_report.invoke({ reportId: 'rid-9' })).restored, { id: 'rid-9', key: 'hostkey' });
});

test('0.1.3 R03: onRecovery runs before signing; if it fails nothing is signed', async () => {
  const order = [];
  const s = server();
  const wrapped = async (input, init) => { const req = input instanceof Request ? input : new Request(input, init); if (req.headers.get('PAYMENT-SIGNATURE')) order.push('signed'); return s.fetch(input, init); };
  const out = JSON.parse(await actions({ fetch: wrapped, onRecovery: r => { order.push(['stored', r.reportId, r.recoveryKey, r.path].join(':')); } }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(out.status, 'PASS');
  assert.deepEqual(order, ['stored:rid-1:rkey-1:/api/token-risk', 'signed']);
  const f = server();
  const failed = JSON.parse(await actions({ fetch: f.fetch, onRecovery: async () => { throw new Error('disk full'); } }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(failed.paymentStatus, 'not_paid');
  assert.match(failed.message, /onRecovery failed/);
  assert.ok(f.seen.every(r => !r.signature));
});

test('0.1.3 R04: invalid JSON with HTTP 200 is an explicit error, never an empty success', async () => {
  const paid = JSON.parse(await actions({ fetch: server({ badJson: true }).fetch }).kushbitx_token_risk.invoke({ address: USDC_BASE }));
  assert.equal(paid.error, true);
  assert.equal(paid.paymentStatus, 'unknown');
  assert.match(paid.message, /invalid JSON with HTTP 200/);
  assert.equal(paid.recovery.reportId, 'rid-1');
  const free = JSON.parse(await actions({ fetch: server({ freeBadJson: true }).fetch }).kushbitx_spendguard_evaluate.invoke({
    agentId: 'a', requestId: 'r', recipient: PAY_TO, amount: '5.00',
    policy: { maxPerTransaction: '10', remainingDailyBudget: '50', requireHumanAbove: '25', maxRepeats: 3, allowedRecipients: [PAY_TO], blockUnknownRecipients: true } }));
  assert.equal(free.error, true);
  assert.match(free.message, /invalid JSON/);
});
