# @kushbitx/agentkit

[Coinbase AgentKit](https://github.com/coinbase/agentkit) action provider for [KushBitx](https://kushbitx.com/developers): safety checks for AI agents that pay on Base.

| Action | Price | What it does |
|---|---|---|
| `kushbitx_spendguard_evaluate` | free | Checks a proposed Base USDC payment against your spending policy before paying: APPROVE, HUMAN_APPROVAL or BLOCK. |
| `kushbitx_quick_check` | 0.001 USDC | Base chain identity and official USDC contract presence. |
| `kushbitx_token_risk` | 0.001 USDC | Sellability, taxes, privileged controls, holder concentration and market risk for a Base token. |
| `kushbitx_transaction_preflight` | 0.001 USDC | Simulates an unsigned Base transaction before you sign it. |
| `kushbitx_verify_payment` | 0.00288 USDC | Verifies a Base USDC transfer from its transaction hash. |

Paid actions are paid per call with [x402](https://x402.org), signed by your agent's own AgentKit EVM wallet on Base mainnet. Current prices: https://kushbitx.com/pricing.

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
  actionProviders: [kushbitxActionProvider({ maxPaymentUsdc: "0.01" })],
});
```

## Safety limits

- **Per-call cap:** `maxPaymentUsdc` (default `0.01`). A higher price is refused before anything is signed.
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
