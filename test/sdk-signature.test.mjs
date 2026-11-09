// SDK 0.1.6: typedDataDigest (local EIP-712, embedded keccak) and canSignTypedData for Signature Check reports.
// The fixed digests below were checked against the KushBitx server encoder and viem. Run: node --test test/sdk-signature.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { typedDataDigest, canSignTypedData, paidServices } from '../kushbitx.mjs';

const SIGNER = '0x0d68028d06af13379c872fee032568b4be712f22';
const PAYTO = '0x1111111111111111111111111111111111111111';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';

const eip3009 = (message = {}, domain = {}) => ({
  domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: USDC, ...domain },
  types: { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] },
  primaryType: 'TransferWithAuthorization',
  message: { from: SIGNER, to: PAYTO, value: '1000', validAfter: '0', validBefore: '1900000000', nonce: '0x' + 'ab'.repeat(32), ...message }
});
const permit2Witness = {
  domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 },
  types: {
    PermitBatchWitnessTransferFrom: [{ name: 'permitted', type: 'TokenPermissions[]' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'witness', type: 'Order' }],
    TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }],
    Order: [{ name: 'note', type: 'string' }, { name: 'data', type: 'bytes' }, { name: 'ok', type: 'bool' }, { name: 'delta', type: 'int256' }, { name: 'tag', type: 'bytes4' }]
  },
  primaryType: 'PermitBatchWitnessTransferFrom',
  message: { permitted: [{ token: USDC, amount: '5' }, { token: PAYTO, amount: '7' }], spender: PAYTO, nonce: '99', deadline: '1794244395', witness: { note: 'héllo ' + 'x'.repeat(300), data: '0x' + 'cd'.repeat(200), ok: true, delta: '-5', tag: '0xdeadbeef' } }
};

test('typedDataDigest: EIP-712 Mail vector and fixed KushBitx digests', () => {
  const mail = {
    domain: { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' },
    types: { Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }], Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }] },
    primaryType: 'Mail',
    message: { from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' }, to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' }, contents: 'Hello, Bob!' }
  };
  assert.equal(typedDataDigest(mail), '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2');
  assert.equal(typedDataDigest(eip3009()), '0x2ab9bec789a7aa5aeb7d535926b53bea747c0447fb1d3d70d3f4e6c5259e4eb2');
  assert.equal(typedDataDigest(permit2Witness), '0xd63ec62c45ab5c91087e4aeae2281dc3dfd4c06e52732e8ae46c5a1325a0eb0c');
});

test('typedDataDigest throws on malformed typed data', () => {
  assert.throws(() => typedDataDigest({}), /domain, types, primaryType and message/);
  assert.throws(() => typedDataDigest({ ...eip3009(), primaryType: 'Nope' }), /primaryType/);
  assert.throws(() => typedDataDigest(eip3009({ to: 'not-an-address' })), /Invalid address/);
});

test('paidServices lists signature-check', () => {
  assert.equal(paidServices['signature-check'], '/api/signature-check');
});

test('canSignTypedData: true only for ALLOW on the same typed data, signer and chain, before expiresAt', async () => {
  const typedData = eip3009();
  const request = { chainId: 8453, signer: SIGNER, typedData };
  const now = Date.parse('2026-11-09T12:00:00Z');
  const report = { service: 'signature-check', verdict: 'ALLOW', chainId: 8453, signer: SIGNER, typedDataDigest: typedDataDigest(typedData), expiresAt: new Date(now + 60000).toISOString() };
  assert.equal(await canSignTypedData(report, request, now), true);
  assert.equal(await canSignTypedData(report, { ...request, typedData: eip3009({ to: '0x' + '2'.repeat(40) }) }, now), false, 'changed recipient');
  assert.equal(await canSignTypedData(report, { ...request, typedData: eip3009({ value: '1001' }) }, now), false, 'changed amount');
  assert.equal(await canSignTypedData(report, { ...request, signer: '0x' + '3'.repeat(40) }, now), false, 'other signer');
  for (const chainId of [1, '1', '0x1', 84532, undefined, null]) assert.equal(await canSignTypedData(report, { ...request, chainId }, now), false, 'request chainId ' + chainId);
  assert.equal(await canSignTypedData(report, { ...request, typedData: eip3009({}, { chainId: 1 }) }, now), false, 'domain on another chain');
  const { chainId, ...noChainDomain } = typedData.domain;
  const noChain = { ...typedData, domain: noChainDomain };
  assert.equal(await canSignTypedData({ ...report, typedDataDigest: typedDataDigest(noChain) }, { ...request, typedData: noChain }, now), false, 'domain without chainId');
  assert.equal(await canSignTypedData({ ...report, chainId: 1 }, request, now), false, 'report for another chain');
  assert.equal(await canSignTypedData(report, request, Date.parse(report.expiresAt)), false, 'expired');
  assert.equal(await canSignTypedData({ ...report, verdict: 'REVIEW' }, request, now), false, 'REVIEW');
  assert.equal(await canSignTypedData({ ...report, signer: undefined }, request, now), false, 'report without signer');
  assert.equal(await canSignTypedData({ ...report, typedDataDigest: '0x' + '0'.repeat(64) }, request, now), false, 'other digest');
  assert.equal(await canSignTypedData(null, request, now), false);
  assert.equal(await canSignTypedData(report, null, now), false);
});
