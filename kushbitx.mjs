const PAID_SERVICES = Object.freeze({
  'token-risk': '/api/token-risk',
  preflight: '/api/transaction-preflight',
  'transaction-preflight': '/api/transaction-preflight',
  payment: '/api/verify-payment',
  'payment-proof': '/api/verify-payment',
  'verify-payment': '/api/verify-payment',
  // KushBitx Preflight (0.005 USDC): one verdict before money moves. 'preflight' stays Transaction Preflight.
  'kushbitx-preflight': '/api/preflight'
});

function required(value, name) {
  if (!value || typeof value !== 'string') throw new Error(name + ' is required');
  return value;
}

function errorMessage(data) {
  return data && typeof data === 'object' && typeof data.error === 'string' ? data.error : '';
}

// A success needs a JSON object body. null, arrays, scalars and invalid JSON are errors.
function jsonObject({ data, parseError }, status) {
  if (parseError) throw new Error('KushBitx returned invalid JSON with HTTP ' + status, { cause: parseError });
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('KushBitx returned an empty or non-object JSON body with HTTP ' + status);
  return data;
}

export class KushBitxClient {
  constructor({ baseUrl = 'https://kushbitx.com', fetchFn = globalThis.fetch } = {}) {
    if (typeof fetchFn !== 'function') throw new Error('A fetch implementation is required');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchFn;
  }

  async request(path, { method = 'POST', body, bearer, headers = {} } = {}) {
    const response = await this.fetch(this.baseUrl + path, {
      method,
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(bearer ? { authorization: 'Bearer ' + bearer } : {}),
        ...headers
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    // An unreadable body stays visible as data=null; it is never replaced by an empty object.
    let data = null;
    let parseError = null;
    try {
      data = await response.json();
    } catch (error) {
      parseError = error;
    }
    return { response, data, parseError };
  }

  async expect(path, options, statuses = [200]) {
    const result = await this.request(path, options);
    const { status } = result.response;
    if (!statuses.includes(status)) throw new Error(errorMessage(result.data) || 'KushBitx request failed with HTTP ' + status);
    return jsonObject(result, status);
  }

  previewToken(address) {
    return this.expect('/api/token-preview', { body: { chain: 'base', address } });
  }

  evaluateSpend(input) {
    return this.expect('/api/spendguard/evaluate', { body: input });
  }

  createSpendPolicy(policy) {
    return this.expect('/api/spendguard/policies', { body: policy }, [201]);
  }

  getSpendPolicy(policyId, adminKey) {
    return this.expect('/api/spendguard/policies/' + required(policyId, 'policyId'), { method: 'GET', bearer: required(adminKey, 'adminKey') });
  }

  updateSpendPolicy(policyId, adminKey, policy) {
    return this.expect('/api/spendguard/policies/' + required(policyId, 'policyId'), { method: 'PUT', bearer: required(adminKey, 'adminKey'), body: policy });
  }

  requestSpendDecision(input, agentKey) {
    return this.expect('/api/spendguard/decisions', { bearer: required(agentKey, 'agentKey'), body: input });
  }

  getSpendDecision(decisionId, key) {
    return this.expect('/api/spendguard/decisions/' + required(decisionId, 'decisionId'), { method: 'GET', bearer: required(key, 'key') });
  }

  approveSpendDecision(decisionId, adminKey) {
    return this.expect('/api/spendguard/decisions/' + required(decisionId, 'decisionId') + '/approve', { bearer: required(adminKey, 'adminKey') });
  }

  async getPaymentChallenge(service, input) {
    const path = PAID_SERVICES[service];
    if (!path) throw new Error('Unknown paid service');
    const result = await this.request(path, { body: input });
    if (result.response.status !== 402) throw new Error(errorMessage(result.data) || 'Expected an HTTP 402 payment challenge');
    return { service, path, challenge: jsonObject(result, 402), paymentRequired: result.response.headers.get('PAYMENT-REQUIRED') };
  }

  prepareRecovery(service, input) {
    const path = PAID_SERVICES[service];
    if (!path) throw new Error('Unknown paid service');
    return this.expect('/api/orders', { body: { path, input } }, [201]);
  }

  submitPaidCheck(service, input, { paymentSignature, reportId, recoveryKey }) {
    const path = PAID_SERVICES[service];
    if (!path) throw new Error('Unknown paid service');
    return this.expect(path, {
      body: input,
      headers: {
        'PAYMENT-SIGNATURE': required(paymentSignature, 'paymentSignature'),
        'Report-Id': required(reportId, 'reportId'),
        'Recovery-Key': required(recoveryKey, 'recoveryKey')
      }
    }, [200, 202]);
  }

  restoreReport({ id, key, txHash }) {
    return this.expect('/api/orders/recover', { body: { id: required(id, 'id'), key: required(key, 'key'), ...(txHash ? { txHash } : {}) } }, [200, 202]);
  }
}

export const paidServices = PAID_SERVICES;

// Preflight 1.1: the digest the service returns in transactionDigest. Compute it from the transaction you are about
// to sign; sign only when it matches an ALLOW verdict that has not expired.
// sha256 of JSON {chainId,from,to,value,data} in that key order; from, to and data lowercase; value a decimal wei string.
// The transaction's own chainId goes into the digest (default 8453 when absent), so a report for Base never
// matches the same fields on another network.
const BASE_CHAIN_ID = 8453;
function chainIdOf(transaction) {
  const raw = transaction?.chainId;
  if (raw === undefined || raw === null) return BASE_CHAIN_ID;
  if (typeof raw === 'bigint') return Number(raw);
  if (typeof raw === 'string' && /^0x[0-9a-f]+$/i.test(raw)) return Number(BigInt(raw));
  if (typeof raw === 'string' && /^[0-9]+$/.test(raw)) return Number(raw);
  if (typeof raw === 'number' && Number.isInteger(raw)) return raw;
  return NaN;
}
export async function preflightDigest(transaction) {
  const { from = null, to, value = '0', data = '0x' } = transaction || {};
  const chainId = chainIdOf(transaction);
  if (!Number.isInteger(chainId)) throw new Error('chainId must be an integer');
  const canonical = JSON.stringify({ chainId, from: from ? String(from).toLowerCase() : null, to: required(to, 'to').toLowerCase(), value: BigInt(value || '0').toString(), data: String(data || '0x').toLowerCase() });
  const subtle = globalThis.crypto?.subtle ?? (await import('node:crypto')).webcrypto.subtle;
  const hash = await subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return '0x' + Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}

/** True only for an ALLOW verdict on this exact Base transaction (chainId 8453, stated), before expiresAt. Anything else: do not sign. */
export async function canSign(report, transaction, now = Date.now()) {
  if (!report || typeof report !== 'object' || report.verdict !== 'ALLOW' || typeof report.transactionDigest !== 'string') return false;
  // The transaction must state chainId 8453; a missing chainId is never assumed to be Base.
  if (!transaction || typeof transaction !== 'object' || transaction.chainId === undefined || transaction.chainId === null || chainIdOf(transaction) !== BASE_CHAIN_ID) return false;
  if (report.chainId !== undefined && Number(report.chainId) !== BASE_CHAIN_ID) return false;
  if (!report.expiresAt || !(Date.parse(report.expiresAt) > now)) return false;
  try {
    return report.transactionDigest.toLowerCase() === await preflightDigest(transaction);
  } catch {
    return false;
  }
}
