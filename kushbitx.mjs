const PAID_SERVICES = Object.freeze({
  'token-risk': '/api/token-risk',
  preflight: '/api/transaction-preflight',
  'transaction-preflight': '/api/transaction-preflight',
  payment: '/api/verify-payment',
  'payment-proof': '/api/verify-payment',
  'verify-payment': '/api/verify-payment',
  // KushBitx Preflight (0.005 USDC): one verdict before money moves. 'preflight' stays Transaction Preflight.
  'kushbitx-preflight': '/api/preflight',
  // Signature Check (0.003 USDC): ALLOW, REVIEW or BLOCK for an EIP-712 signature request, bound to its digest.
  'signature-check': '/api/signature-check'
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

// Signature Check: the EIP-712 digest the service returns in typedDataDigest, computed locally with no network and
// no dependency: keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(primaryType, message)).
const MASK64 = (1n << 64n) - 1n;
const KECCAK_RC = [0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
const KECCAK_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const rotl64 = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK64);
function keccakF(st) {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map(x => st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]);
    for (let x = 0; x < 5; x++) { const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) st[y + x] ^= d; }
    const b = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], KECCAK_ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & MASK64 & b[(x + 2) % 5 + 5 * y]);
    st[0] ^= KECCAK_RC[round];
  }
}
function keccak256(bytes) {
  const rate = 136, st = new Array(25).fill(0n);
  const padded = new Uint8Array(Math.floor(bytes.length / rate) * rate + rate);
  padded.set(bytes); padded[bytes.length] ^= 0x01; padded[padded.length - 1] ^= 0x80;
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) { let lane = 0n; for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]); st[i] ^= lane; }
    keccakF(st);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((st[i] >> BigInt(8 * j)) & 0xffn);
  return out;
}
const hexBytes = hex => { const h = String(hex).replace(/^0x/i, ''); if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error('Invalid hex in typedData'); return Uint8Array.from(h.match(/../g) || [], b => parseInt(b, 16)); };
const concatBytes = parts => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const utf8 = text => new TextEncoder().encode(String(text));
const word256 = n => hexBytes(BigInt.asUintN(256, BigInt(n)).toString(16).padStart(64, '0'));
function typeDeps(primary, types, found = new Set()) {
  const base = primary.replace(/\[.*$/, '');
  if (found.has(base) || !types[base]) return found;
  found.add(base);
  for (const field of types[base]) typeDeps(field.type, types, found);
  return found;
}
function encodeType(primary, types) {
  return [primary, ...[...typeDeps(primary, types)].filter(t => t !== primary).sort()].map(t => {
    if (!Array.isArray(types[t])) throw new Error('Unknown type in typedData: ' + t);
    return t + '(' + types[t].map(f => f.type + ' ' + f.name).join(',') + ')';
  }).join('');
}
function encodeValue(type, value, types) {
  if (types[type]) return hashStruct(type, value, types);
  const array = type.match(/^(.*)\[(\d*)\]$/);
  if (array) {
    if (!Array.isArray(value)) throw new Error('Expected an array for ' + type);
    if (array[2] !== '' && value.length !== Number(array[2])) throw new Error('Wrong array length for ' + type);
    return keccak256(concatBytes(value.map(v => encodeValue(array[1], v, types))));
  }
  if (type === 'string') return keccak256(utf8(value));
  if (type === 'bytes') return keccak256(hexBytes(value));
  if (type === 'bool') return word256(value === true || value === 'true' ? 1 : 0);
  if (type === 'address') { if (!/^0x[0-9a-fA-F]{40}$/.test(String(value))) throw new Error('Invalid address in typedData'); return word256(BigInt(value)); }
  const bytesN = type.match(/^bytes(\d+)$/);
  if (bytesN) { const b = hexBytes(value); if (b.length !== Number(bytesN[1])) throw new Error('Wrong length for ' + type); const out = new Uint8Array(32); out.set(b); return out; }
  const int = type.match(/^(u?)int(\d*)$/);
  if (int) { const n = BigInt(value); if (int[1] === 'u' && (n < 0n || n >= 1n << BigInt(Number(int[2] || 256)))) throw new Error('Value out of range for ' + type); return word256(n); }
  throw new Error('Unsupported type in typedData: ' + type);
}
function hashStruct(primary, data, types) {
  if (!data || typeof data !== 'object') throw new Error('Missing struct value for ' + primary);
  return keccak256(concatBytes([keccak256(utf8(encodeType(primary, types))), ...types[primary].map(f => encodeValue(f.type, data[f.name], types))]));
}
const DOMAIN_FIELDS = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address'], ['salt', 'bytes32']];
/** EIP-712 digest of typed data ({domain, types, primaryType, message}), as 0x-hex. Same value as typedDataDigest in a Signature Check report. */
export function typedDataDigest(typedData) {
  const { domain, types, primaryType, message } = typedData || {};
  if (!domain || !types || !primaryType || !message) throw new Error('typedData needs domain, types, primaryType and message');
  const own = Object.fromEntries(Object.entries(types).filter(([k]) => k !== 'EIP712Domain'));
  if (!own[primaryType]) throw new Error('primaryType is not defined in types');
  const domainTypes = { EIP712Domain: DOMAIN_FIELDS.filter(([n]) => domain[n] !== undefined && domain[n] !== null).map(([name, type]) => ({ name, type })) };
  const digest = keccak256(concatBytes([new Uint8Array([0x19, 0x01]), hashStruct('EIP712Domain', domain, domainTypes), hashStruct(primaryType, message, own)]));
  return '0x' + Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
}

// secp256k1 public-key recovery (no dependency), used only to verify KushBitx signed verdicts.
const SECP_P = 2n ** 256n - 2n ** 32n - 977n;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const modp = (a, m = SECP_P) => { const r = a % m; return r >= 0n ? r : r + m; };
function modInv(a, m) { let [x, y, u, v] = [0n, 1n, m, modp(a, m)]; while (v !== 0n) { const q = u / v; [x, y] = [y, x - q * y]; [u, v] = [v, u - q * v]; } if (u !== 1n) throw new Error('no inverse'); return modp(x, m); }
function modPow(b, e, m) { let r = 1n; b = modp(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
// Jacobian coordinates [X, Y, Z]; null is the point at infinity.
function jDouble(P) { if (!P || P[1] === 0n) return null; const [X, Y, Z] = P; const S = modp(4n * X * Y * Y), M = modp(3n * X * X), X3 = modp(M * M - 2n * S); return [X3, modp(M * (S - X3) - 8n * Y ** 4n), modp(2n * Y * Z)]; }
function jAdd(P, Q) {
  if (!P) return Q; if (!Q) return P;
  const [X1, Y1, Z1] = P, [X2, Y2, Z2] = Q, Z1s = modp(Z1 * Z1), Z2s = modp(Z2 * Z2);
  const U1 = modp(X1 * Z2s), U2 = modp(X2 * Z1s), S1 = modp(Y1 * Z2s * Z2), S2 = modp(Y2 * Z1s * Z1);
  if (U1 === U2) return S1 === S2 ? jDouble(P) : null;
  const H = modp(U2 - U1), R = modp(S2 - S1), H2 = modp(H * H), H3 = modp(H2 * H), X3 = modp(R * R - H3 - 2n * U1 * H2);
  return [X3, modp(R * (U1 * H2 - X3) - S1 * H3), modp(H * Z1 * Z2)];
}
function jMul(P, k) { let R = null, A = P; while (k > 0n) { if (k & 1n) R = jAdd(R, A); A = jDouble(A); k >>= 1n; } return R; }
function toAffine(P) { if (!P) return null; const zi = modInv(P[2], SECP_P), zi2 = modp(zi * zi); return [modp(P[0] * zi2), modp(P[1] * zi2 * zi)]; }
const hex32 = n => n.toString(16).padStart(64, '0');
/** Address that produced a 65-byte r,s,v signature over a 32-byte digest, or null. Rejects high s and v other than 27/28. */
export function recoverAddress(digestHex, signatureHex) {
  try {
    const sig = String(signatureHex).replace(/^0x/i, ''), dig = String(digestHex).replace(/^0x/i, '');
    if (!/^[0-9a-f]{130}$/i.test(sig) || !/^[0-9a-f]{64}$/i.test(dig)) return null;
    const r = BigInt('0x' + sig.slice(0, 64)), s = BigInt('0x' + sig.slice(64, 128)), v = parseInt(sig.slice(128), 16);
    if ((v !== 27 && v !== 28) || r <= 0n || r >= SECP_N || s <= 0n || s > SECP_N / 2n) return null;
    const y2 = modp(r ** 3n + 7n); let y = modPow(y2, (SECP_P + 1n) / 4n, SECP_P);
    if (modp(y * y) !== y2) return null;
    if ((y & 1n) !== BigInt(v - 27)) y = SECP_P - y;
    const e = BigInt('0x' + dig) % SECP_N, rInv = modInv(r, SECP_N);
    const Q = toAffine(jAdd(jMul([SECP_G[0], SECP_G[1], 1n], modp(-e * rInv, SECP_N)), jMul([r, y, 1n], modp(s * rInv, SECP_N))));
    if (!Q) return null;
    const hash = keccak256(hexBytes(hex32(Q[0]) + hex32(Q[1])));
    return '0x' + Array.from(hash.slice(12), b => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}

const VERDICT_PRIMARY_TYPES = ['PreflightVerdict', 'SignatureVerdict'];
/**
 * Verifies a KushBitx signedVerdict (Preflight or Signature Check): the domain is KushBitx Preflight / 1 / 8453, the
 * primaryType is the one expected, the EIP-712 digest recomputes, and the signature recovers to signedVerdict.signer.
 * options.signers: addresses listed as active at /.well-known/kushbitx-preflight-signers.json; pass them for full trust.
 * options.primaryType: 'PreflightVerdict' or 'SignatureVerdict' (always pass it; the two are never interchangeable).
 * Returns { valid, signer, reason }. Never throws.
 */
export function verifySignedVerdict(signedVerdict, options = {}) {
  const fail = reason => ({ valid: false, signer: null, reason });
  try {
    if (!signedVerdict || typeof signedVerdict !== 'object') return fail('no signedVerdict');
    const td = signedVerdict.typedData, d = td?.domain;
    if (!td || !d || d.name !== 'KushBitx Preflight' || String(d.version) !== '1' || chainIdOf({ chainId: d.chainId }) !== BASE_CHAIN_ID) return fail('wrong domain');
    if (!VERDICT_PRIMARY_TYPES.includes(td.primaryType) || (options.primaryType && td.primaryType !== options.primaryType)) return fail('wrong primaryType');
    const digest = typedDataDigest(td);
    if (String(signedVerdict.digest || '').toLowerCase() !== digest) return fail('digest does not match the typed data');
    const signer = recoverAddress(digest, signedVerdict.signature);
    if (!signer || signer !== String(signedVerdict.signer || '').toLowerCase()) return fail('bad signature');
    if (Array.isArray(options.signers) && !options.signers.map(a => String(a).toLowerCase()).includes(signer)) return fail('signer not in the trusted list');
    return { valid: true, signer, reason: null };
  } catch { return fail('malformed signedVerdict'); }
}

/**
 * True only for an ALLOW Signature Check report on this exact typed data, for this signer, on Base, before expiresAt.
 * request: { chainId: 8453 (stated), signer, typedData }. typedData.domain.chainId must also be 8453: a signature
 * without a chain in its domain could be replayed elsewhere, so it is never accepted. Anything else: do not sign.
 * When the report carries signedVerdict, it must also verify: a SignatureVerdict for the same typedDataDigest and
 * signer, chainId 8453, ALLOW, not expired, with a valid KushBitx signature. options.signers (active addresses from
 * /.well-known/kushbitx-preflight-signers.json) restricts the key; options.requireSigned makes signedVerdict mandatory.
 */
export async function canSignTypedData(report, request, now = Date.now(), options = {}) {
  if (!report || typeof report !== 'object' || report.verdict !== 'ALLOW' || typeof report.typedDataDigest !== 'string') return false;
  if (!request || typeof request !== 'object' || request.chainId === undefined || request.chainId === null || chainIdOf(request) !== BASE_CHAIN_ID) return false;
  if (report.chainId !== undefined && Number(report.chainId) !== BASE_CHAIN_ID) return false;
  const domainChain = request.typedData?.domain?.chainId;
  if (domainChain === undefined || domainChain === null || chainIdOf({ chainId: domainChain }) !== BASE_CHAIN_ID) return false;
  if (typeof request.signer !== 'string' || typeof report.signer !== 'string' || request.signer.toLowerCase() !== report.signer.toLowerCase()) return false;
  if (!report.expiresAt || !(Date.parse(report.expiresAt) > now)) return false;
  let local;
  try { local = typedDataDigest(request.typedData); } catch { return false; }
  if (report.typedDataDigest.toLowerCase() !== local) return false;
  const sv = report.signedVerdict;
  if (sv === undefined || sv === null) return !options.requireSigned;
  const m = sv.typedData?.message;
  if (!m || String(m.typedDataDigest || '').toLowerCase() !== local || String(m.signer || '').toLowerCase() !== request.signer.toLowerCase()) return false;
  if (Number(m.chainId) !== BASE_CHAIN_ID || Number(m.verdict) !== 1 || !(Number(m.expiresAt) * 1000 > now)) return false;
  return verifySignedVerdict(sv, { primaryType: 'SignatureVerdict', signers: options.signers }).valid;
}
