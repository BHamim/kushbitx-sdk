// SDK 0.1.2+: invalid JSON is never hidden and a null/non-object body is never a success.
// Run: node --test test/sdk.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { KushBitxClient, preflightDigest, canSign } from '../kushbitx.mjs';

const client = (body, status = 200, headers = {}) => new KushBitxClient({
  fetchFn: async () => new Response(body, { status, headers })
});

test('valid JSON object on an expected status is returned', async () => {
  assert.deepEqual(await client('{"allowed":true}').evaluateSpend({}), { allowed: true });
});

test('invalid JSON on an expected status throws and keeps the parse error as cause', async () => {
  await assert.rejects(client('<html>oops</html>').evaluateSpend({}), error => {
    assert.match(error.message, /invalid JSON with HTTP 200/);
    assert.ok(error.cause instanceof SyntaxError);
    return true;
  });
});

test('JSON null, empty body, array and scalar are not successes', async () => {
  for (const body of ['null', '', '[]', '42', '"ok"']) {
    await assert.rejects(client(body, 201).createSpendPolicy({}), /HTTP 201/, `body ${JSON.stringify(body)}`);
  }
});

test('unexpected status uses the server error message, or the status when the body is unreadable', async () => {
  await assert.rejects(client('{"error":"Policy not found"}', 404).getSpendPolicy('p', 'k'), /^Error: Policy not found$/);
  await assert.rejects(client('not json', 500).getSpendPolicy('p', 'k'), /HTTP 500/);
  await assert.rejects(client('null', 500).getSpendPolicy('p', 'k'), /HTTP 500/);
});

test('402 challenge needs a JSON object body', async () => {
  const ok = await client('{"x402Version":2}', 402, { 'PAYMENT-REQUIRED': 'abc' }).getPaymentChallenge('token-risk', {});
  assert.deepEqual(ok.challenge, { x402Version: 2 });
  assert.equal(ok.paymentRequired, 'abc');
  await assert.rejects(client('null', 402).getPaymentChallenge('token-risk', {}), /HTTP 402/);
  await assert.rejects(client('bad', 402).getPaymentChallenge('token-risk', {}), /invalid JSON with HTTP 402/);
  await assert.rejects(client('{"x402Version":2}', 200).getPaymentChallenge('token-risk', {}), /Expected an HTTP 402/);
});

test('restore accepts 202 with a JSON object and rejects 202 null', async () => {
  assert.deepEqual(await client('{"status":"pending"}', 202).restoreReport({ id: 'a', key: 'b' }), { status: 'pending' });
  await assert.rejects(client('null', 202).restoreReport({ id: 'a', key: 'b' }), /HTTP 202/);
});

// Preflight 1.1: the SDK digest equals the one the service returned on staging for the same USDC transfer (2026-10-31).
const TX = { chainId: 8453, from: '0x0d68028d06af13379C872FEE032568B4Be712f22', to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', value: '0', data: '0xa9059cbb000000000000000000000000d2db751a2fdba554706fb535438d81d3a0b4297900000000000000000000000000000000000000000000000000000000000003e8' };
test('preflightDigest matches the service digest; canSign needs ALLOW, the same transaction and time left', async () => {
  const digest = await preflightDigest(TX);
  assert.match(digest, /^0xaf8cc51219f597/);
  const later = new Date(Date.now() + 60000).toISOString();
  assert.equal(await canSign({ verdict: 'ALLOW', transactionDigest: digest, expiresAt: later }, TX), true);
  assert.equal(await canSign({ verdict: 'ALLOW', transactionDigest: digest, expiresAt: later }, { ...TX, value: '1' }), false);
  assert.equal(await canSign({ verdict: 'REVIEW', transactionDigest: digest, expiresAt: later }, TX), false);
  assert.equal(await canSign({ verdict: 'ALLOW', transactionDigest: digest, expiresAt: new Date(Date.now() - 1).toISOString() }, TX), false);
});

// SDK 0.1.4 (external review 2026-10-31): canSign must refuse another network and any changed digest field.
test('canSign refuses another chainId, a changed to, data, value or from, an expired or non-Base report', async () => {
  const digest = await preflightDigest(TX);
  const later = new Date(Date.now() + 60000).toISOString();
  const ok = { verdict: 'ALLOW', chainId: 8453, transactionDigest: digest, expiresAt: later };
  assert.equal(await canSign(ok, TX), true);
  assert.equal(await canSign(ok, { ...TX, chainId: 8453 }), true);
  assert.equal(await canSign(ok, { ...TX, chainId: '0x2105' }), true, 'hex 8453 is Base');
  for (const chainId of [1, '1', '0x1', 84532, 10, 'base', 8453.5, null === 0]) assert.equal(await canSign(ok, { ...TX, chainId }), false, 'chainId ' + chainId);
  assert.equal(await canSign(ok, { ...TX, to: '0x' + '9'.repeat(40) }), false, 'to');
  assert.equal(await canSign(ok, { ...TX, data: TX.data.slice(0, -1) + '9' }), false, 'data');
  assert.equal(await canSign(ok, { ...TX, value: '1' }), false, 'value');
  assert.equal(await canSign(ok, { ...TX, from: '0x' + '2'.repeat(40) }), false, 'from');
  assert.equal(await canSign(ok, { ...TX, from: undefined }), false, 'missing from');
  // Second external review: a removed network is never assumed to be Base.
  const { chainId, ...noChain } = TX;
  assert.equal(await canSign(ok, noChain), false, 'missing chainId');
  assert.equal(await canSign(ok, { ...TX, chainId: null }), false, 'null chainId');
  assert.equal(await preflightDigest(noChain), digest, 'the digest itself still defaults to 8453');
  assert.equal(await canSign({ ...ok, expiresAt: new Date(Date.now() - 1).toISOString() }, TX), false, 'expired');
  assert.equal(await canSign({ ...ok, expiresAt: undefined }, TX), false, 'no expiry');
  assert.equal(await canSign({ ...ok, chainId: 1 }, TX), false, 'report for another chain');
  assert.equal(await canSign({ ...ok, verdict: 'REVIEW' }, TX), false, 'REVIEW');
  assert.equal(await canSign(ok, { ...TX, to: undefined }), false, 'missing to');
  assert.equal(await canSign(null, TX), false);
  assert.equal(await canSign(ok, null), false);
  assert.notEqual(await preflightDigest({ ...TX, chainId: 1 }), digest, 'the chainId is part of the digest');
});
