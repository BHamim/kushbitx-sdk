# KushBitx Token Risk as a Franklin PreSpend hook (external, optional)

This hook runs before Franklin's `Base0xSwap` and `Base0xGaslessSwap`. It checks the token being bought with [KushBitx Token Risk](https://kushbitx.com/developers): sellability, owner controls, liquidity and holder concentration. It lets the swap run only on `ALLOW`.

It is not part of Franklin and is not endorsed by BlockRun. It uses Franklin's documented hook contract (`docs/examples/hooks/` in the Franklin repo) and needs no change to Franklin.

## Install

```bash
mkdir -p ~/.blockrun/hooks
cp kushbitx-token-risk.json kushbitx-token-risk.sh kushbitx-token-risk.mjs ~/.blockrun/hooks/
chmod +x ~/.blockrun/hooks/kushbitx-token-risk.sh
cd ~/.blockrun/hooks && npm install @x402/fetch @x402/evm viem
export KUSHBITX_PAYER_KEY=0x...   # a dedicated wallet with a little USDC on Base; it only pays for checks
```

Each check costs 0.001 USDC, paid with x402. The script refuses to pay more than that per call. With a free trial key, set `KUSHBITX_TRIAL_KEY` instead: no payment until the trial ends.

## Limits

- **It sees token names, not the transaction.** Franklin gives a PreSpend hook `{estimatedUsd, tool, params}`. For a swap, that is `sell_token`, `buy_token` and `sell_amount`. The 0x quote, its calldata and the Permit2 signature are built inside the tool, after the hook. So this hook does **not**:
  - simulate the swap,
  - check where the output goes,
  - check approvals,
  - or detect prompt injection.
  It screens the bought token only.
- **Timeouts.** Franklin's default hook timeout is 5 seconds, and a timeout or crash **fails open**: the swap runs. A Token Risk check can take longer than 5 seconds. So the config here sets `"timeout": 30`, and the script stops itself at 25 seconds with a deny. Keep both if you edit the config.
- **Fail-closed.** These all deny the swap: no key, a payment failure, a non-200 answer, an unreadable answer, and any verdict other than `ALLOW`. That includes `INCOMPLETE`, which means missing evidence, never "safe".
- **WARN.** To let `WARN` through when it has no high or critical finding, set `KUSHBITX_ALLOW_WARN=1`.
- **Native ETH.** Buying native ETH is allowed without a check, because there is no token contract to screen.
- **Not advice.** It is automated screening, not an audit and not investment advice.

## Disable

Remove the three files from `~/.blockrun/hooks/`, or run Franklin with `FRANKLIN_HOOKS=0`, which disables all hooks.
