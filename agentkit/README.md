# @kushbitx/agentkit

[Coinbase AgentKit](https://github.com/coinbase/agentkit) action provider for [KushBitx](https://kushbitx.com/developers): safety checks for AI agents that pay on Base.

| Action | Price | What it does |
|---|---|---|
| `kushbitx_preflight_transaction` | 0.005 USDC | **One call before money moves.** Simulates the unsigned transaction, decodes approvals and transfers, screens the token and the recipient, and returns ALLOW, REVIEW or BLOCK with sourced findings; fail-closed. Does not detect prompt injection. Base (chain 8453) only. |
| `kushbitx_spendguard_evaluate` | free | Checks a proposed Base USDC payment against your spending policy before paying: APPROVE, HUMAN_APPROVAL or BLOCK. |
| `kushbitx_quick_check` | 0.001 USDC | Base chain identity and official USDC contract presence. |
| `kushbitx_token_risk` | 0.001 USDC | Sellability, taxes, privileged controls, holder concentration and market risk for a Base token. |
| `kushbitx_transaction_preflight` | 0.001 USDC | Simulates an unsigned Base transaction before you sign it. |
| `kushbitx_verify_payment` | 0.00288 USDC | Verifies a Base USDC transfer from its transaction hash. |
| `kushbitx_restore_report` | free | Restores a paid report after `paymentStatus` "unknown" or "pending", from its `reportId`. Never pays again. |

Paid actions are paid per call with [x402](https://x402.org), signed by your agent's own AgentKit EVM wallet on Base mainnet. Current prices: https://kushbitx.com/api/services.

## Install

```bash
npm install @kushbitx/agentkit @coinbase/agentkit zod
```

## Use

```js
import { AgentKit } from "@coinbase/agentkit";
import { kushbitxActionProvider } from "@kushbitx/agentkit";

const agentkit = await AgentKit.from({
  walletProvider, // any AgentKit EVM wallet provider on Base mainnet
  actionProviders: [kushbitxActionProvider({ maxPaymentUsdc: "0.005" })], // keep the wallet key in .env (EVM_PRIVATE_KEY), never in code
});
```

## Preflight 1.1

`kushbitx_preflight_transaction` returns `canSign`. It is true only for ALLOW on the exact transaction the agent sent (same `transactionDigest`), before `expiresAt` (60 seconds). Send `from`, otherwise the verdict is REVIEW. For swaps add `expectedTokenOut`, and optionally `minAmountOut` and `expectedRecipient`.

## Payment status and recovery

Before signing a payment, each paid action prepares recovery credentials (`POST /api/orders`) and sends them with the paid request. The result says `paymentStatus`:

- `not_paid`: nothing was signed, or the server rejected the authorization before settlement.
- `unknown`: an authorization was signed but no report arrived, or the server answered with a body that is not valid JSON. **Do not pay again.** Call `kushbitx_restore_report` with the `reportId` in `recovery` to get the report if the payment settled.
- `pending`: the report is still processing; restore it the same way.

### Recovery keys stay out of the model's context (0.1.3)

The recovery key is a secret: whoever has it can read the report. From 0.1.3 it is **never** written into an action's output; the model only sees `reportId`.

- The provider keeps the key in memory for this process, and the free action `kushbitx_restore_report` (`reportId`, optional `txHash`) uses it to call `POST /api/orders/recover`.
- To survive a restart, pass `onRecovery`. It receives `{ reportId, recoveryKey, expiresAt, path }` **before anything is signed**, and it must succeed: if it throws or rejects, the call ends with `not_paid` and nothing is signed. Pass `getRecoveryKey(reportId)` so `kushbitx_restore_report` can read the key back from your store.

```js
kushbitxActionProvider({
  maxPaymentUsdc: "0.005",
  onRecovery: async r => store.set(r.reportId, r.recoveryKey),   // your database, file or secret store
  getRecoveryKey: async id => store.get(id),
});
```

`chainId: 8453` is required in the action input (it is never assumed). `canSign` is false for any other chainId and for a report for another chain. `canSign` and `digestMatches` are always computed locally and written last; if the server sends fields with those names, they are kept only under `server` for diagnosis.

## Safety limits

- **Per-call caps:**
  - `maxPaymentUsdc` (default `0.005`) is the **overall** cap: no action pays more than this for one call, `kushbitx_preflight_transaction` included.
  - `maxPreflightUsdc` (default `0.005`) is an extra cap for Preflight only. Preflight uses the **lower** of the two.
  - Example: `maxPaymentUsdc: "0.001"` refuses Preflight (0.005) before anything is signed. Before 0.1.3, Preflight used `maxPreflightUsdc` alone.
  - A higher price is refused before anything is signed; the caps protect you if a price changes.
- **Invalid responses:** a reply that is not a JSON object is an explicit error, never an empty success (same rule as `@kushbitx/sdk`).
- **Only our exact requirement is signed:** `exact` scheme, Base (`eip155:8453`), USDC, paid to `0x0d68028d06af13379C872FEE032568B4Be712f22`. Anything else is refused before signing.
- **Base mainnet only** for paid actions. SpendGuard is free on any network.
- KushBitx never receives keys, never signs and never moves funds. `INCOMPLETE` means missing evidence, never zero risk.

Requests carry `x-kushbitx-channel: agentkit` so we can count AgentKit usage. No personal data is added.

## Links

- Developers: https://kushbitx.com/developers
- MCP server: https://kushbitx.com/mcp
- Terms: https://kushbitx.com/terms · Privacy: https://kushbitx.com/privacy
- Contact: admin@kushbitx.com

License: Apache-2.0
