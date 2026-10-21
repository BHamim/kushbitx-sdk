const PAID_SERVICES = Object.freeze({
  'token-risk': '/api/token-risk',
  preflight: '/api/transaction-preflight',
  'transaction-preflight': '/api/transaction-preflight',
  payment: '/api/verify-payment',
  'payment-proof': '/api/verify-payment',
  'verify-payment': '/api/verify-payment'
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
