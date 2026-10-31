// @kushbitx/agentkit — Coinbase AgentKit action provider for KushBitx (https://kushbitx.com/developers).
// Free: SpendGuard spend-policy check. Paid per call via x402 (USDC on Base), signed by the agent's own
// AgentKit EVM wallet: KushBitx Preflight (one verdict), Quick Check, Token Risk, Transaction Preflight, Payment Verification.
// KushBitx never receives keys. Payments outside the limits below are refused before anything is signed.
import { customActionProvider, EvmWalletProvider } from '@coinbase/agentkit';
import { wrapFetchWithPayment, x402Client } from '@x402/fetch';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { z } from 'zod';
import { createHash } from 'node:crypto';

export const KUSHBITX_ORIGIN = 'https://kushbitx.com';
export const PAY_TO = '0x0d68028d06af13379C872FEE032568B4Be712f22';
export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const BASE_NETWORK = 'eip155:8453';
const VERSION = '0.1.1';
const address = z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'a 0x-prefixed 40-hex address');

/** Accept only our exact requirement: Base USDC, paid to KushBitx, at or below the per-call cap (atomic units). */
export function paymentPolicy(maxAtomic) {
  return (_version, requirements) => requirements.filter(r =>
    r.scheme === 'exact' && r.network === BASE_NETWORK &&
    String(r.asset).toLowerCase() === USDC_BASE.toLowerCase() &&
    String(r.payTo).toLowerCase() === PAY_TO.toLowerCase() &&
    /^\d+$/.test(String(r.amount)) && BigInt(r.amount) > 0n && BigInt(r.amount) <= maxAtomic);
}

function toAtomic(usdc) {
  if (!/^(0|[1-9]\d*)(\.\d{1,6})?$/.test(String(usdc))) throw new Error('maxPaymentUsdc must be a decimal USDC amount with up to 6 places');
  const [whole, frac = ''] = String(usdc).split('.');
  return BigInt(whole) * 1000000n + BigInt(frac.padEnd(6, '0'));
}

const SPENDGUARD = z.object({
  agentId: z.string().min(1).max(80).describe('Your agent identifier'),
  requestId: z.string().min(1).max(120).describe('Unique id for this payment request'),
  recipient: address.describe('Base address that would receive the payment'),
  amount: z.string().describe('Decimal USDC amount, e.g. "5.00"'),
  policy: z.object({
    maxPerTransaction: z.string(), remainingDailyBudget: z.string(), requireHumanAbove: z.string(),
    maxRepeats: z.number().int().min(0).max(100), allowedRecipients: z.array(address).max(50), blockUnknownRecipients: z.boolean()
  }).describe('Spending policy to check against (decimal USDC strings)'),
  context: z.object({ repeatCount: z.number().int().min(0).optional(), agentProofDecision: z.enum(['ALLOW', 'WARN', 'BLOCK', 'INCOMPLETE', 'UNKNOWN']).optional() }).optional()
});

/**
 * @param {object} [options]
 * @param {string} [options.maxPaymentUsdc="0.005"] Highest price the agent may pay for one call (enough for every KushBitx check). Protects you if a price changes.
 * @param {string} [options.maxPreflightUsdc="0.005"] Highest price for one KushBitx Preflight call (its price is 0.005 USDC).
 * @param {string} [options.origin="https://kushbitx.com"] API origin (https://staging.kushbitx.com refuses settlement).
 * @param {typeof fetch} [options.fetch] Fetch implementation (tests).
 * @param {Record<string,string>} [options.headers] Extra request headers, e.g. {"x-kushbitx-traffic": "test"}.
 */
/** Preflight 1.1 digest: sha256 of JSON {chainId,from,to,value,data}; from, to and data lowercase; value in decimal wei. */
export function preflightDigest({ from = null, to, value = '0', data = '0x' }) {
  return '0x' + createHash('sha256').update(JSON.stringify({ chainId: 8453, from: from ? String(from).toLowerCase() : null, to: String(to).toLowerCase(), value: BigInt(value || '0').toString(), data: String(data || '0x').toLowerCase() })).digest('hex');
}
// Adds canSign: true only for ALLOW whose digest matches the transaction the agent sent, before expiresAt.
function withSignDecision(text, args) {
  let report;
  try { report = JSON.parse(text); } catch { return text; }
  if (!report || typeof report !== 'object' || !report.verdict) return text;
  const digestMatches = report.transactionDigest === preflightDigest(args);
  const canSign = report.verdict === 'ALLOW' && digestMatches && Date.parse(report.expiresAt) > Date.now();
  return JSON.stringify({ canSign, digestMatches, ...report }, null, 2);
}

export function kushbitxActionProvider(options = {}) {
  const origin = (options.origin || KUSHBITX_ORIGIN).replace(/\/$/, '');
  if (!/^https:\/\/(staging\.)?kushbitx\.com$/.test(origin)) throw new Error('origin must be https://kushbitx.com or https://staging.kushbitx.com');
  const maxAtomic = toAtomic(options.maxPaymentUsdc ?? '0.005');
  const maxPreflightAtomic = toAtomic(options.maxPreflightUsdc ?? '0.005');
  const baseFetch = options.fetch || globalThis.fetch;
  const headers = { ...(options.headers || {}), 'x-kushbitx-channel': 'agentkit', 'user-agent': 'kushbitx-agentkit/' + VERSION };

  const call = async (doFetch, path, method, body) => {
    const response = await doFetch(origin + path, { method, headers: { ...headers, ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const data = await response.json().catch(() => ({}));
    if (response.status === 200) return JSON.stringify(data, null, 2);
    if (response.status === 202) return JSON.stringify({ status: 'pending', reportId: data.reportId, message: 'Payment or report processing is pending. Do not pay again; restore with POST ' + origin + '/api/orders/recover.' });
    return JSON.stringify({ error: true, status: response.status, message: data.error || 'Request failed' });
  };

  const paid = (path, method, cap = maxAtomic, capText = options.maxPaymentUsdc ?? '0.005') => async (walletProvider, args) => {
    if (!(walletProvider instanceof EvmWalletProvider) && typeof walletProvider?.toSigner !== 'function') return JSON.stringify({ error: true, message: 'KushBitx paid checks need an EVM wallet provider on Base.' });
    const network = walletProvider.getNetwork?.();
    if (network && network.chainId !== undefined && String(network.chainId) !== '8453') return JSON.stringify({ error: true, message: 'KushBitx paid checks run on Base mainnet (chain 8453); this wallet is on ' + (network.networkId || network.chainId) + '.' });
    const account = walletProvider.toSigner();
    const signer = { ...account, address: account.address ?? walletProvider.getAddress(), readContract: a => walletProvider.readContract(a) };
    const client = new x402Client();
    registerExactEvmScheme(client, { signer });
    client.registerPolicy(paymentPolicy(cap));
    try {
      return await call(wrapFetchWithPayment(baseFetch, client), path, method, method === 'POST' ? args : undefined);
    } catch (error) {
      return JSON.stringify({ error: true, message: 'Payment not made: ' + (error?.message || 'x402 payment failed') + '. Limit: ' + capText + ' USDC per call, Base USDC to KushBitx only.' });
    }
  };

  return customActionProvider([
    { name: 'kushbitx_spendguard_evaluate',
      description: 'Free. Check a proposed Base USDC payment against a spending policy (per-transaction limit, daily budget, human-approval threshold, allowed recipients) BEFORE paying. Returns APPROVE, HUMAN_APPROVAL or BLOCK with findings. Advisory only; never signs or moves funds.',
      schema: SPENDGUARD,
      invoke: async args => call(baseFetch, '/api/spendguard/evaluate', 'POST', { ...args, chain: 'base', asset: 'USDC' }) },
    { name: 'kushbitx_preflight_transaction',
      description: 'Paid (0.005 USDC via x402 on Base). Call ONCE before signing any Base swap, transfer, approval or token buy, with the exact unsigned transaction and from (the signing wallet; without it the verdict is REVIEW). For swaps add expectedTokenOut, and optionally minAmountOut and expectedRecipient. Simulates the transaction and every transfer and approval it causes, screens the token and the recipient, and returns one verdict: ALLOW, REVIEW (ask the user; also when a check could not run) or BLOCK (do not sign). Sign only when canSign is true: ALLOW for this exact transaction, before expiresAt (60 seconds). It does not detect prompt injection.',
      schema: z.object({ chainId: z.literal(8453).default(8453), to: address.describe('Contract or recipient address'), from: address.optional().describe('Signing wallet'), value: z.string().regex(/^[0-9]+$/).optional().describe('ETH value in wei'), data: z.string().regex(/^0x([0-9a-fA-F]{2})*$/).optional().describe('Unsigned calldata hex'), intent: z.enum(['swap', 'transfer', 'approve', 'buy_token', 'contract_call']).optional(), tokenAddress: address.optional().describe('Token to screen when it is not the destination'), amount: z.string().regex(/^[0-9]+(\.[0-9]{1,18})?$/).optional().describe('Amount in token units'), expectedRecipient: address.optional().describe('Swap: who must receive the output (default from)'), minAmountOut: z.string().regex(/^[0-9]+(\.[0-9]{1,36})?$/).optional().describe('Swap: smallest acceptable output, in token units'), expectedTokenOut: address.optional().describe('Swap: token the swap must deliver; 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE for native ETH') }),
      invoke: async (walletProvider, args) => withSignDecision(await paid('/api/preflight', 'POST', maxPreflightAtomic, options.maxPreflightUsdc ?? '0.005')(walletProvider, args), args) },
    { name: 'kushbitx_quick_check',
      description: 'Paid (0.001 USDC via x402 on Base). Confirms Base chain identity and the official USDC contract presence. Not a token-risk report.',
      schema: z.object({}),
      invoke: paid('/api/agentproof-quick-check', 'GET') },
    { name: 'kushbitx_token_risk',
      description: 'Paid (0.001 USDC via x402 on Base). Screens a Base token for sellability, taxes, privileged controls, holder concentration and market risk. INCOMPLETE means missing evidence, never zero risk.',
      schema: z.object({ chain: z.literal('base').default('base'), address: address.describe('Base token contract address') }),
      invoke: paid('/api/token-risk', 'POST') },
    { name: 'kushbitx_transaction_preflight',
      description: 'Paid (0.001 USDC via x402 on Base). Simulates an UNSIGNED Base transaction and flags failed execution, dangerous approvals and destination risk before you sign it.',
      schema: z.object({ chain: z.literal('base').default('base'), to: address.describe('Contract or recipient address'), from: address.optional().describe('Sender address'), data: z.string().regex(/^0x([0-9a-fA-F]{2})*$/).optional().describe('Calldata hex'), valueWei: z.string().regex(/^[0-9]+$/).optional().describe('ETH value in wei') }),
      invoke: paid('/api/transaction-preflight', 'POST') },
    { name: 'kushbitx_verify_payment',
      description: 'Paid (0.00288 USDC via x402 on Base). Verifies a Base USDC transfer (recipient, amount, confirmations) from its transaction hash.',
      schema: z.object({ chain: z.literal('base').default('base'), txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/), expectedTo: address, expectedAmount: z.string().regex(/^[0-9]+(\.[0-9]{1,6})?$/).describe('Decimal USDC, e.g. "10.00"'), expectedFrom: address.optional() }),
      invoke: paid('/api/verify-payment', 'POST') }
  ]);
}

export default kushbitxActionProvider;
