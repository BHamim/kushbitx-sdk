#!/usr/bin/env node
// KushBitx Preflight 1.1 for Clodds (external skill). Fail-closed: exit 0 only on ALLOW for this exact transaction.
// Usage: node preflight.mjs '{"from":"0x...","to":"0x...","value":"0","data":"0x...","intent":"swap","expectedTokenOut":"0x..."}'
// Needs: npm install @x402/fetch @x402/evm viem, and KUSHBITX_PAYER_KEY (a dedicated wallet that only pays for checks).
import { createHash } from 'node:crypto';

const ENDPOINT = 'https://kushbitx.com/api/preflight';
const MAX_PER_CALL = '$0.005'; // refuse to pay more if the price ever changes
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;

const stop = (reason, extra = {}) => { console.log(JSON.stringify({ sign: false, reason, ...extra })); process.exit(2); };

let tx;
try { tx = JSON.parse(process.argv[2] || ''); } catch { stop('Pass the unsigned transaction as one JSON argument'); }
if (!ADDRESS.test(tx.from || '')) stop('from (the signing wallet) is required');
if (!ADDRESS.test(tx.to || '')) stop('to is required');
if (!/^[0-9]+$/.test(String(tx.value ?? '0'))) stop('value must be a decimal wei string');
if (!process.env.KUSHBITX_PAYER_KEY) stop('KUSHBITX_PAYER_KEY is not set');

const input = { chainId: 8453, ...tx, value: String(tx.value ?? '0'), data: tx.data || '0x' };
// The same digest the service returns: sha256 of {chainId,from,to,value,data}, lowercase, value in decimal wei.
const digest = '0x' + createHash('sha256').update(JSON.stringify({ chainId: 8453, from: input.from.toLowerCase(), to: input.to.toLowerCase(), value: BigInt(input.value).toString(), data: input.data.toLowerCase() })).digest('hex');

let response, body;
try {
  const { x402Client, wrapFetchWithPayment } = await import('@x402/fetch');
  const { registerExactEvmScheme } = await import('@x402/evm/exact/client');
  const { privateKeyToAccount } = await import('viem/accounts');
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.KUSHBITX_PAYER_KEY) });
  client.setSpendControls({ maxAmountPerPayment: MAX_PER_CALL });
  const paidFetch = wrapFetchWithPayment(fetch, client);
  response = await paidFetch(ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input), signal: AbortSignal.timeout(60000) });
  body = await response.json();
} catch (error) { stop('Preflight unavailable: ' + String(error?.message || error).slice(0, 200)); }

if (response.status !== 200) stop('Preflight returned HTTP ' + response.status, { error: body?.error });
const summary = { verdict: body.verdict, reasonCodes: body.reasonCodes, checksUnavailable: body.checksUnavailable, transactionDigest: body.transactionDigest, expiresAt: body.expiresAt };
if (body.transactionDigest !== digest) stop('Digest mismatch: the checked transaction is not the one given', summary);
if (Date.parse(body.expiresAt) <= Date.now()) stop('The verdict has already expired', summary);
if (body.verdict !== 'ALLOW') stop(body.verdict, { ...summary, findings: body.findings });
console.log(JSON.stringify({ sign: true, ...summary }));
