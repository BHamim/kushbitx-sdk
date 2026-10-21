# KushBitx SDK

Zero-dependency ESM client and runnable Node.js example for the complete KushBitx AgentProof service suite on Base.

## Services

| Service | Price | Purpose |
| --- | ---: | --- |
| Token market preview | Free | Inspect basic Base token market data without connecting a wallet. |
| Data coverage check | Free | See which risk checks have enough evidence before buying a report. |
| SpendGuard | Free pilot | Evaluate payment policy before money moves, with optional protected policies and human approval. |
| Token-risk report | 0.25 USDC | Receive structured token-risk evidence with missing checks identified. |
| Transaction preflight | 0.05 USDC | Inspect an unsigned Base transaction before signing. |
| Payment verification | 0.01 USDC | Verify an existing Base USDC payment against the expected recipient and amount. |

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
- Contact: Admin@kushbitx.com

## Community contributions

- [@mengxin10086](https://github.com/mengxin10086) built an independent MCP bridge for the free KushBitx endpoints. KushBitx reviewed and accepted commit `0e4d3226` ([source at that commit](https://github.com/mengxin10086/kushbitx-mcp-agent/tree/0e4d32267d4692d32cfb7c451d391cd59093a883)). It is third-party code, maintained by its author.

## Security

Do not disclose suspected vulnerabilities in public issues. Report them privately to Admin@kushbitx.com.

## License

The SDK and examples are available under the Apache License 2.0. Hosted services, risk models, proprietary rules, and non-public components are not included in that license.
