# KushBitx SDK

Zero-dependency ESM client and runnable Node.js example for the complete KushBitx AgentProof service suite on Base.

## Services

| Service | Price | Purpose |
| --- | ---: | --- |
| Token market preview | Free | Inspect basic Base token market data without connecting a wallet. |
| Data coverage check | Free | See which risk checks have enough evidence before buying a report. |
| SpendGuard | Free pilot | Evaluate payment policy before money moves, with optional protected policies and human approval. |
| Token-risk report | 0.001 USDC | Receive structured token-risk evidence with missing checks identified. |
| Transaction preflight | 0.001 USDC | Inspect an unsigned Base transaction before signing. |
| Payment verification | 0.00288 USDC | Verify an existing Base USDC payment against the expected recipient and amount. |
| KushBitx Preflight | 0.005 USDC | One verdict (ALLOW, REVIEW, BLOCK) before money moves, fail-closed: transaction simulation, approval and transfer decoding, token and recipient screening, optional protected SpendGuard policy. Does not detect prompt injection; Protected SpendGuard can cap what an agent pays if your signer enforces it, but does not detect prompt injection either. Service name `kushbitx-preflight`. |

Paid endpoints use x402 and require explicit payment. There is no subscription. A delivered report can be `INCOMPLETE` when evidence is unavailable and may still incur the displayed fee.

## Quick start

Node.js 22 or later:

```js
import { KushBitxClient } from './kushbitx.mjs';

const kushbitx = new KushBitxClient();

const preview = await kushbitx.previewToken(
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
);

console.log(preview);
```

The SDK never requests, stores, or signs with a private key. It can discover an x402 challenge, prepare recovery, submit an externally signed payment authorization, and recover a report.

## TypeScript

Types ship with the package (`kushbitx.d.ts`), including `PreflightInput` and `PreflightReport`:

```ts
import { KushBitxClient, type PreflightInput } from '@kushbitx/sdk';

const kushbitx = new KushBitxClient();
const input: PreflightInput = { chainId: 8453, to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', data: '0x', intent: 'contract_call' };
const { challenge } = await kushbitx.getPaymentChallenge('kushbitx-preflight', input); // HTTP 402, nothing charged
```

### Preflight 1.1: sign only the transaction that was checked

Send `from`; without it the verdict is REVIEW. `canSign` needs the transaction to state `chainId: 8453`; a missing or other chainId is never accepted. Each response has `transactionDigest` and `expiresAt` (60 seconds). For swaps, add `expectedTokenOut`, and optionally `minAmountOut` and `expectedRecipient`.

```js
import { canSign } from '@kushbitx/sdk';

const tx = { chainId: 8453, from: wallet, to, value: '0', data };   // the exact unsigned transaction
// ... pay for POST /api/preflight with your x402 client, get `report` ...
if (await canSign(report, tx)) {
  // ALLOW, same digest, not expired: sign now
} else {
  // REVIEW, BLOCK, another network, changed transaction or expired: do not sign
}
```

Required checks per transaction type: `requiredChecks` in https://kushbitx.com/api/services.

Current prices: https://kushbitx.com/api/services

## Runnable example

Download `agent.mjs`, then run a free flow without installing packages:

```bash
node agent.mjs
node agent.mjs --spendguard
```

Paid flows are deliberately opt-in. They require `--paid`, a dedicated local wallet, and `viem`:

```bash
npm install viem
node agent.mjs --paid --service=token-risk
```

The example validates the network, asset, recipient, exact price, timeout, and USDC signing domain before creating a signature. It prepares recovery before payment and never trades or executes the transaction being inspected.

## Direct browser import

The current hosted SDK is also available at:

```js
import { KushBitxClient } from 'https://kushbitx.com/sdk/kushbitx.mjs';
```

## Links

- Website: https://kushbitx.com
- Source: https://github.com/BHamim/kushbitx-sdk
- Tools: https://kushbitx.com/#tools
- SpendGuard: https://kushbitx.com/spendguard
- Integration example: https://kushbitx.com/examples/agent.mjs
- Clodds skill (optional, external): [integrations/clodds/kushbitx-preflight](integrations/clodds/kushbitx-preflight). Copy the folder into .clodds/skills/ to run KushBitx Preflight before signing Base transactions. Not part of CloddsBot and not endorsed by its maintainers.
- Franklin PreSpend hook (optional, external): [integrations/franklin/kushbitx-token-risk](integrations/franklin/kushbitx-token-risk). Screens the token a Base0xSwap buys with KushBitx Token Risk before the swap runs. It sees token names, not the transaction; read its limits first. Not part of Franklin and not endorsed by BlockRun.
- Contact: Admin@kushbitx.com

## Community contributions

- [@mengxin10086](https://github.com/mengxin10086) built an independent MCP bridge for the free KushBitx endpoints. KushBitx reviewed and accepted commit `0e4d3226` ([source at that commit](https://github.com/mengxin10086/kushbitx-mcp-agent/tree/0e4d32267d4692d32cfb7c451d391cd59093a883)). It is third-party code, maintained by its author.

## Security

Do not disclose suspected vulnerabilities in public issues. Report them privately to Admin@kushbitx.com.

## License

The SDK and examples are available under the Apache License 2.0. Hosted services, risk models, proprietary rules, and non-public components are not included in that license.
