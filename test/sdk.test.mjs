// SDK 0.1.2: invalid JSON is never hidden and a null/non-object body is never a success.
// Run: node --test test/sdk.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { KushBitxClient } from '../kushbitx.mjs';

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
