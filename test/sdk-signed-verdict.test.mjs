// SDK 0.1.7: verifySignedVerdict, recoverAddress and canSignTypedData with a signed SignatureVerdict.
// The vector was signed by the KushBitx server signer code with a throwaway test key (0x22...22), never a real key.
// Run: node --test test/sdk-signed-verdict.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { canSignTypedData, verifySignedVerdict, recoverAddress } from '../kushbitx.mjs';

const V = {
  "testKeyAddress": "0x1563915e194d8cfba1943570603f7606a3115508",
  "typedData": {
    "domain": {
      "name": "USD Coin",
      "version": "2",
      "chainId": 8453,
      "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    },
    "types": {
      "TransferWithAuthorization": [
        {
          "name": "from",
          "type": "address"
        },
        {
          "name": "to",
          "type": "address"
        },
        {
          "name": "value",
          "type": "uint256"
        },
        {
          "name": "validAfter",
          "type": "uint256"
        },
        {
          "name": "validBefore",
          "type": "uint256"
        },
        {
          "name": "nonce",
          "type": "bytes32"
        }
      ]
    },
    "primaryType": "TransferWithAuthorization",
    "message": {
      "from": "0x0d68028d06af13379c872fee032568b4be712f22",
      "to": "0x1111111111111111111111111111111111111111",
      "value": "1000",
      "validAfter": "0",
      "validBefore": "1794485100",
      "nonce": "0xabababababababababababababababababababababababababababababababab"
    }
  },
  "report": {
    "service": "signature-check",
    "verdict": "ALLOW",
    "typedDataDigest": "0x3959860be69476278c2e8eb8b17b45ab0f1f84b2d75ad24c4a146ba255538ad6",
    "chainId": 8453,
    "signer": "0x0d68028d06af13379c872fee032568b4be712f22",
    "expiresAt": "2026-11-12T12:01:00.000Z",
    "signedVerdict": {
      "scheme": "eip712",
      "primaryType": "SignatureVerdict",
      "keyId": "test-key",
      "signer": "0x1563915e194d8cfba1943570603f7606a3115508",
      "rulesVersion": "kushbitx-signature-check/1.0/2026-11-12",
      "typedData": {
        "domain": {
          "name": "KushBitx Preflight",
          "version": "1",
          "chainId": 8453
        },
        "types": {
          "EIP712Domain": [
            {
              "name": "name",
              "type": "string"
            },
            {
              "name": "version",
              "type": "string"
            },
            {
              "name": "chainId",
              "type": "uint256"
            }
          ],
          "SignatureVerdict": [
            {
              "name": "signer",
              "type": "address"
            },
            {
              "name": "chainId",
              "type": "uint256"
            },
            {
              "name": "typedDataDigest",
              "type": "bytes32"
            },
            {
              "name": "verdict",
              "type": "uint8"
            },
            {
              "name": "issuedAt",
              "type": "uint64"
            },
            {
              "name": "expiresAt",
              "type": "uint64"
            },
            {
              "name": "rulesVersion",
              "type": "bytes32"
            },
            {
              "name": "requestId",
              "type": "bytes32"
            }
          ]
        },
        "primaryType": "SignatureVerdict",
        "message": {
          "signer": "0x0d68028d06af13379c872fee032568b4be712f22",
          "chainId": 8453,
          "typedDataDigest": "0x3959860be69476278c2e8eb8b17b45ab0f1f84b2d75ad24c4a146ba255538ad6",
          "verdict": 1,
          "issuedAt": 1794484800,
          "expiresAt": 1794484860,
          "rulesVersion": "0x9e714a3004145257ccf7d3e2c4455b69d61ae5bc832f7631ae83f6dfbe420daa",
          "requestId": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
      },
      "digest": "0x349042f8db546a20e96d59a0f6f593f54e5cbca66170097e24735632bf54ca55",
      "signature": "0x82f11120b7bbce6ab5216b4744b179d2d6e259f713d93307d9f85f8d665b346a2a514e1297e491cce4412f5d4a84820e9e32093933c7e84a962a460aa56b4df91b"
    }
  }
};
const NOW = Date.parse('2026-11-12T12:00:30Z');
const request = { chainId: 8453, signer: V.report.signer, typedData: V.typedData };
const clone = o => JSON.parse(JSON.stringify(o));

test('a valid signed verdict verifies and recovers to the test key', async () => {
  assert.equal(recoverAddress(V.report.signedVerdict.digest, V.report.signedVerdict.signature), V.testKeyAddress);
  assert.deepEqual(verifySignedVerdict(V.report.signedVerdict, { primaryType: 'SignatureVerdict', signers: [V.testKeyAddress] }), { valid: true, signer: V.testKeyAddress, reason: null });
  assert.equal(await canSignTypedData(V.report, request, NOW, { signers: [V.testKeyAddress], requireSigned: true }), true);
});

test('never accepted as a PreflightVerdict, from another key, after expiry, or when changed', async () => {
  assert.equal(verifySignedVerdict(V.report.signedVerdict, { primaryType: 'PreflightVerdict' }).valid, false);
  assert.equal(await canSignTypedData(V.report, request, NOW, { signers: ['0x' + '99'.repeat(20)] }), false);
  assert.equal(await canSignTypedData(V.report, request, Date.parse('2026-11-12T12:01:01Z')), false);
  const changed = clone(V.report); changed.signedVerdict.typedData.message.requestId = '0x' + 'dd'.repeat(32);
  assert.equal(await canSignTypedData(changed, request, NOW), false);
  const forged = clone(V.report); forged.signedVerdict.signature = forged.signedVerdict.signature.replace(/.$/, c => (c === 'b' ? 'c' : 'b'));
  assert.equal(await canSignTypedData(forged, request, NOW), false);
  const otherPayee = clone(request); otherPayee.typedData.message.to = '0x' + '55'.repeat(20);
  assert.equal(await canSignTypedData(V.report, otherPayee, NOW), false);
  const unsigned = clone(V.report); unsigned.signedVerdict = null;
  assert.equal(await canSignTypedData(unsigned, request, NOW, { requireSigned: true }), false);
  assert.equal(await canSignTypedData(unsigned, request, NOW), true, 'unsigned reports keep the 0.1.6 behaviour');
});
