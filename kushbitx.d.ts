// Type declarations for @kushbitx/sdk 0.1.3. The SDK never requests, stores or signs with a private key.

/** Paid service names accepted by the payment helpers, and the route each one calls. */
export type PaidService =
  | 'token-risk'
  | 'preflight' | 'transaction-preflight'
  | 'payment' | 'payment-proof' | 'verify-payment'
  | 'kushbitx-preflight';

export declare const paidServices: Readonly<Record<PaidService, string>>;

export interface ClientOptions {
  /** API origin. Default https://kushbitx.com (use https://staging.kushbitx.com for the Testnet sandbox). */
  baseUrl?: string;
  /** Fetch implementation. Default globalThis.fetch. */
  fetchFn?: typeof fetch;
}

export type Address = `0x${string}`;
export type Verdict = 'ALLOW' | 'WARN' | 'BLOCK' | 'INCOMPLETE';

export interface TokenInput { chain: 'base'; address: Address }
export interface TransactionInput { chain: 'base'; to: Address; from?: Address; valueWei?: string; data?: `0x${string}` }
export interface PaymentProofInput { chain: 'base'; txHash: `0x${string}`; expectedTo: Address; expectedAmount: string; expectedFrom?: Address }

/** Input of KushBitx Preflight (POST /api/preflight, 0.005 USDC). */
export interface PreflightInput {
  chainId: 8453;
  to: Address;
  /** Signing wallet. Required in practice: without it the verdict is REVIEW (sender_unknown). */
  from?: Address;
  /** Native ETH value in wei. */
  value?: string;
  data?: `0x${string}`;
  intent?: 'swap' | 'transfer' | 'approve' | 'buy_token' | 'contract_call';
  tokenAddress?: Address;
  amount?: string;
  /** Protected SpendGuard policy; send the agent key as Authorization: Bearer. Base USDC transfers only. */
  policy?: { policyId: string; agentId: string; requestId: string };
  /** Swap: who must receive the output. Default: from. */
  expectedRecipient?: Address;
  /** Swap: smallest acceptable output, in token units (for example "25.5"). */
  minAmountOut?: string;
  /** Swap: token the swap must deliver; 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE for native ETH. */
  expectedTokenOut?: Address;
}

export type PreflightTransactionType = 'native_transfer' | 'erc20_transfer' | 'approval' | 'swap' | 'contract_call';

export interface PreflightFinding {
  code: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  kind: 'fact' | 'inference';
  message: string;
  source: string;
  sourceTimestamp: string;
  onchainBlock: number | null;
  evidence?: Record<string, unknown>;
}

export interface PreflightReport {
  /** "1.1" since 2026-10-31. */
  reportVersion: string;
  service: 'preflight';
  generatedAt: string;
  checkedAt: string;
  /** checkedAt + 60 seconds. Do not sign after this time. */
  expiresAt: string;
  /** Compare with preflightDigest(transaction) before signing. */
  transactionDigest: `0x${string}`;
  transactionDigestMethod: string;
  validity: string;
  transactionType: PreflightTransactionType;
  /** Checks this transaction type needs; a missing one gives REVIEW. */
  requiredChecks: string[];
  /** Simulated transfers and approvals (eth_simulateV1), and the swap output check. */
  effects: { simulated: boolean; transfers?: Array<Record<string, unknown>>; approvals?: Array<Record<string, unknown>>; swap?: { expectedRecipient: Address; expectedTokenOut: Address; receivedAtomic: string; minAmountOutAtomic: string | null }; error?: string } | null;
  input: Record<string, unknown>;
  chainId: 8453;
  onchainBlock: number | null;
  verdict: 'ALLOW' | 'REVIEW' | 'BLOCK';
  /** What Preflight does not check, such as prompt injection. */
  notChecked: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  reasonCodes: string[];
  findings: PreflightFinding[];
  checksPerformed: string[];
  checksUnavailable: string[];
  limitations: string[];
  reports: Record<string, unknown>;
  attribution?: { text: string; url: string; logo: string; scope: string };
}

export interface SpendPolicy {
  maxPerTransaction: string;
  remainingDailyBudget: string;
  requireHumanAbove: string;
  maxRepeats: number;
  allowedRecipients: Address[];
  blockUnknownRecipients: boolean;
}

export interface SpendInput {
  agentId: string;
  requestId: string;
  chain: 'base';
  asset: 'USDC';
  recipient: Address;
  amount: string;
  policy: SpendPolicy;
  context?: { repeatCount?: number; agentProofDecision?: 'ALLOW' | 'WARN' | 'BLOCK' | 'INCOMPLETE' | 'UNKNOWN' };
}

export interface PaymentChallenge {
  service: PaidService;
  path: string;
  /** The 402 JSON body (x402Version, accepts, resource). */
  challenge: Record<string, unknown>;
  /** The base64 PAYMENT-REQUIRED header, for an x402 client. */
  paymentRequired: string | null;
}

export interface RecoveryCredentials { id: string; key: string; [k: string]: unknown }

/** The digest KushBitx Preflight returns in transactionDigest, computed locally from the transaction you will sign. */
export declare function preflightDigest(transaction: { chainId?: number | string | bigint; from?: Address | null; to: Address; value?: string; data?: string }): Promise<`0x${string}`>;
/** True only for ALLOW on this exact Base transaction before expiresAt. chainId must be stated and be 8453; a missing or other chainId, or any changed field, is false. */
export declare function canSign(report: PreflightReport | Record<string, unknown>, transaction: { chainId: number | string | bigint; from?: Address | null; to: Address; value?: string; data?: string }, now?: number): Promise<boolean>;

export declare class KushBitxClient {
  constructor(options?: ClientOptions);
  baseUrl: string;
  request(path: string, options?: { method?: string; body?: unknown; bearer?: string; headers?: Record<string, string> }): Promise<{ response: Response; data: unknown; parseError: unknown }>;
  expect<T = Record<string, unknown>>(path: string, options?: { method?: string; body?: unknown; bearer?: string; headers?: Record<string, string> }, statuses?: number[]): Promise<T>;

  /** Free market preview; no risk verdict. */
  previewToken(address: Address): Promise<Record<string, unknown>>;
  /** Free SpendGuard check. Advisory only: the caller supplies the policy. */
  evaluateSpend(input: SpendInput): Promise<Record<string, unknown>>;
  createSpendPolicy(policy: Record<string, unknown>): Promise<Record<string, unknown>>;
  getSpendPolicy(policyId: string, adminKey: string): Promise<Record<string, unknown>>;
  updateSpendPolicy(policyId: string, adminKey: string, policy: Record<string, unknown>): Promise<Record<string, unknown>>;
  requestSpendDecision(input: Record<string, unknown>, agentKey: string): Promise<Record<string, unknown>>;
  getSpendDecision(decisionId: string, key: string): Promise<Record<string, unknown>>;
  approveSpendDecision(decisionId: string, adminKey: string): Promise<Record<string, unknown>>;

  /** Ask for the x402 challenge (HTTP 402). Nothing is charged. */
  getPaymentChallenge(service: 'kushbitx-preflight', input: PreflightInput): Promise<PaymentChallenge>;
  getPaymentChallenge(service: 'token-risk', input: TokenInput): Promise<PaymentChallenge>;
  getPaymentChallenge(service: 'preflight' | 'transaction-preflight', input: TransactionInput): Promise<PaymentChallenge>;
  getPaymentChallenge(service: 'payment' | 'payment-proof' | 'verify-payment', input: PaymentProofInput): Promise<PaymentChallenge>;
  /** Store recovery credentials before signing, so an interrupted call can be restored without paying again. */
  prepareRecovery(service: PaidService, input: object): Promise<RecoveryCredentials>;
  /** Send an externally signed payment (PAYMENT-SIGNATURE). Returns the report, or a pending status (HTTP 202). */
  submitPaidCheck(service: 'kushbitx-preflight', input: PreflightInput, auth: { paymentSignature: string; reportId: string; recoveryKey: string }): Promise<PreflightReport | Record<string, unknown>>;
  submitPaidCheck(service: PaidService, input: object, auth: { paymentSignature: string; reportId: string; recoveryKey: string }): Promise<Record<string, unknown>>;
  restoreReport(args: { id: string; key: string; txHash?: string }): Promise<Record<string, unknown>>;
}
