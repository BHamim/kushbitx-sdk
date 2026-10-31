---
name: kushbitx-preflight
description: "Before signing any Base (chain 8453) transaction, get one ALLOW/REVIEW/BLOCK verdict on the exact unsigned transaction from KushBitx Preflight (x402, 0.005 USDC). Sign only on ALLOW."
emoji: "🛂"
gates:
  envs:
    - KUSHBITX_PAYER_KEY
  bins:
    - node
---

# KushBitx Preflight before signing (Base)

An optional, external check. It runs only when you install this folder and set `KUSHBITX_PAYER_KEY`. It does not change Clodds' own risk engine, circuit breakers or keystore.

## Setup

```bash
cd .clodds/skills/kushbitx-preflight
npm install @x402/fetch @x402/evm viem
export KUSHBITX_PAYER_KEY=0x...   # a dedicated wallet with a small USDC balance on Base, used only to pay for checks
```

Each check costs 0.005 USDC, paid with x402 v2. The script refuses to pay more than 0.005 per call. The payer key only pays for checks. It never signs the trade. Your trading wallet stays in Clodds' keystore.

## When to use

Use it before signing any Base transaction: swaps (Uniswap, Aerodrome, 1inch, Odos, Virtuals), token transfers, and approvals.

1. Build the unsigned transaction as usual (`populateTransaction`). Do not sign it yet.
2. Run the check with the exact fields you will sign. Give `value` as a decimal wei string.
   ```bash
   node .clodds/skills/kushbitx-preflight/preflight.mjs '{"from":"<trading wallet>","to":"<to>","value":"<wei>","data":"<calldata>","intent":"swap","expectedTokenOut":"<token you buy>","minAmountOut":"<minimum, token units>"}'
   ```
   - `from` is required, otherwise the result is REVIEW.
   - For swaps, add `expectedTokenOut` (use `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` for native ETH), and optionally `minAmountOut` and `expectedRecipient` (default `from`).
   - For anything else, use `intent` `transfer`, `approve`, `buy_token` or `contract_call`.
3. Act on the result. The script prints one JSON line.
   - **Exit 0, `"sign": true`:** the verdict is ALLOW and its `transactionDigest` matches this exact transaction. Sign and send it now, before `expiresAt` (60 seconds). If any field changes or the time passes, run the check again.
   - **Any other exit code:** do not sign. That covers REVIEW, BLOCK, a digest mismatch, a timeout, a payment problem and an unset key. Show `reason`, `reasonCodes`, `checksUnavailable` and `findings` to the user, and wait for an explicit yes.
   - **Never change inputs to get a different verdict.**

## Limits

- Preflight does not detect prompt injection. Keep Clodds' own limits on.
- It checks one transaction against current Base state. It is not an audit and not financial advice.
- Required checks per transaction type are listed in `https://kushbitx.com/api/services` (`requiredChecks`). If any is missing, the verdict is REVIEW.
- Docs: https://kushbitx.com/developers#preflight-1-1
