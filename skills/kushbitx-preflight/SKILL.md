---
name: kushbitx-preflight
description: Check a Base transaction or an EIP-712 payment signature with KushBitx before the agent signs it. Use when an agent is about to sign or send a transaction on Base (eip155:8453), approve a token, swap, send USDC, or sign an x402 / EIP-3009 payment authorization. Returns ALLOW, REVIEW or BLOCK; sign only on ALLOW. Paid per check via x402 (USDC on Base) or prepaid credits; no signup or API key.
license: Apache-2.0
metadata:
  author: KushBitx
  homepage: https://kushbitx.com
  version: "0.1.0-draft"
---

# KushBitx Preflight: check before you sign (Base)

KushBitx checks a transaction or a signature request **before** the agent signs it. It never holds keys, signs transactions or moves funds. The agent's own wallet signs; KushBitx only answers whether it is safe to sign.

## When to use
- Before signing or sending **any transaction on Base**: transfers, approvals, swaps, contract calls, batches, smart-account calls, UserOperations, EIP-7702 authorizations. Use **KushBitx Preflight** (`POST https://kushbitx.com/api/preflight`).
- Before signing an **EIP-712 payment authorization** (EIP-3009 `TransferWithAuthorization`, as used by x402), use **Signature Check** (`POST https://kushbitx.com/api/signature-check`).
- Not for other chains: Base mainnet (chainId 8453) only.

## The rule: fail-closed (always)
Sign **only** when all of these hold:
1. The HTTP status is 200 and the response has `verdict: "ALLOW"`.
2. For Preflight, the transaction you will sign is exactly the one checked: `transactionDigest` matches (use `canSign` from `@kushbitx/sdk`), and you sign **before `expiresAt`** (60 seconds).
3. You did not change `to`, `value`, `data`, `from` or the chain after the check.

**Batches, smart-account calls, UserOperations and EIP-7702 authorizations (Beta):** these have no `transactionDigest`, so `canSign` returns false for them. Sign only on `ALLOW`, before `expiresAt`, after verifying `executionDigest` against the exact calls (and authorizations) you will submit, in the same order. If you cannot verify `executionDigest`, treat the result as `REVIEW` and do not sign.

**Never sign** on `REVIEW`, on `BLOCK`, on any error, timeout, non-200 status, missing or unknown verdict, or an expired report. On REVIEW, stop and ask a human, or drop the action. A timeout is never treated as ALLOW.

## Prices and payment
- Current prices: `GET https://kushbitx.com/api/services` (the single source; do not hardcode prices).
- **x402:** the first request returns HTTP 402 with a `PAYMENT-REQUIRED` header. Nothing is charged until a signed payment is sent. Before paying, check: network `eip155:8453`, asset USDC, `payTo` and amount, and cap what you pay per call. Any x402 v2 client works (for example `@x402/fetch`). Copy-ready snippets: https://kushbitx.com/developers
- **Prepaid credits:** send `X-KushBitx-Credit-Key: <key>` and a unique `Idempotency-Key` per check (8–128 characters). No 402 step. A retry with the same Idempotency-Key and the same input returns the stored result and is not charged again. Keep the credit key in a secret store, never in code, prompts or logs. Top-up and balance: https://kushbitx.com/developers
- If a check fails on our side and returns a technical REVIEW, credits are returned automatically.

## KushBitx Preflight
Request (single transaction):
```json
{
  "chainId": 8453,
  "from": "0xYourAgentWallet",
  "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "value": "0",
  "data": "0xa9059cbb…",
  "intent": "transfer",
  "expectedRecipient": "0xIntendedRecipient"
}
```
- Always send `from` (otherwise the verdict is REVIEW).
- Swaps: add `expectedTokenOut` (and optionally `minAmountOut`, `expectedRecipient`).
- Beta: `calls` (batch, up to 10), smart-account calls, UserOperations and `authorizationList` (EIP-7702) are accepted at the same price. A call KushBitx does not interpret gives REVIEW. `canSign` returns false for batches: do not sign one call of a batch on its own.

Read the response:
- `verdict`: `ALLOW`, `REVIEW` or `BLOCK`.
- `findings` / `reasonCodes`: why, with sources.
- `transactionDigest`, `expiresAt`: bind the verdict to this transaction for 60 seconds.
- `technicalReview: true`: REVIEW only because a required check could not run. Still do not sign; retry later.
- `executionDigest` and, **on ALLOW only**, `signedVerdict` (Beta): an EIP-712 `PreflightVerdict` signed by a KushBitx key, valid at most 60 seconds. Accept it only if its signer is listed as active at https://kushbitx.com/.well-known/kushbitx-preflight-signers.json. REVIEW and BLOCK carry `signedVerdict: null`. A signed ALLOW covers the chain state at the block used, not the future.

Check before signing (Node.js):
```js
import { canSign } from "@kushbitx/sdk";
const report = await res.json();                     // response from POST /api/preflight
if (res.status !== 200 || !(await canSign(report, tx))) {
  throw new Error("KushBitx: do not sign (" + (report?.verdict ?? res.status) + ")");
}
// sign and send tx now, before report.expiresAt
```

## Signature Check (EIP-712 / x402 payment authorizations)
Request:
```json
{
  "chainId": 8453,
  "signer": "0xYourAgentWallet",
  "typedData": { "domain": {…}, "types": {…}, "primaryType": "TransferWithAuthorization", "message": {…} },
  "expectedPayTo": "0xSellerYouMeanToPay",
  "expectedAmount": "1000"
}
```
- Always send `expectedPayTo` and `expectedAmount` (atomic units). A different payee or amount returns BLOCK (`PAYTO_MISMATCH`, `AMOUNT_MISMATCH`).
- Long validity windows return REVIEW (`LONG_AUTHORIZATION`). x402 payments normally use a few minutes.
- Sign the typed data only on `ALLOW`, only the exact typed data you sent (`typedDataDigest`), only as the same signer, and before `expiresAt`. `canSignTypedData(report, request)` from `@kushbitx/sdk` checks all of this; anything else means do not sign.

## MCP
Remote MCP server (Streamable HTTP): `https://kushbitx.com/mcp`. Tools: `kushbitx_preflight` (paid), `spendguard_evaluate` (free) and others. Paid tools use x402.

## Limits (say them honestly)
- Advisory: KushBitx does not detect prompt injection and does not stop a wallet that ignores the verdict. The agent's signer must enforce "ALLOW only".
- REVIEW and missing evidence are never "safe". INCOMPLETE or null scores in other KushBitx checks mean missing evidence, never zero risk.
- Terms, refunds and privacy: https://kushbitx.com/terms, https://kushbitx.com/privacy

More: https://kushbitx.com/llms.txt · https://kushbitx.com/openapi.json · https://kushbitx.com/developers
