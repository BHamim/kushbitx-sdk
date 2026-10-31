#!/usr/bin/env node
// Franklin PreSpend hook (external, optional): screens the token a Base swap buys with KushBitx Token Risk before
// Franklin executes Base0xSwap or Base0xGaslessSwap. Fail-closed: any error, timeout or non-ALLOW verdict denies.
// Not part of Franklin and not endorsed by BlockRun. Docs: README.md next to this file.
const ENDPOINT = 'https://kushbitx.com/api/token-risk';
const MAX_PER_CALL = '$0.001';
const INTERNAL_TIMEOUT_MS = 25000; // the hook's own config sets Franklin's timeout to 30s (default 5s fails open)
const NATIVE_ETH = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
// Same symbols Franklin's Base0xSwap resolves (src/tools/zerox-base.ts).
const SYMBOLS = {
  ETH: NATIVE_ETH, WETH: '0x4200000000000000000000000000000000000006', USDC: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  USDT: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2', CBBTC: '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf',
  CBETH: '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22', AERO: '0x940181a94A35A4569E4529A3CDfB74e38FD98631', DAI: '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb'
};

const deny = reason => { console.log(JSON.stringify({ decision: 'deny', reason: 'KushBitx: ' + reason })); process.exit(2); };
const allow = () => process.exit(0);

let raw = '';
for await (const chunk of process.stdin) raw += chunk;
let event;
try { event = JSON.parse(raw); } catch { deny('could not read the hook input'); }
const params = event?.spend?.params || event?.toolInput || {};
const requested = String(params.buy_token || '').trim();
if (!requested) deny('no buy_token in the swap input');
const token = SYMBOLS[requested.toUpperCase()] || requested;
if (!/^0x[a-fA-F0-9]{40}$/.test(token)) deny('cannot resolve buy_token "' + requested.slice(0, 40) + '" to a Base address');
if (token.toLowerCase() === NATIVE_ETH) allow(); // buying native ETH: no token contract to screen

const timer = setTimeout(() => deny('Token Risk did not answer in time'), INTERNAL_TIMEOUT_MS);
let report;
try {
  const headers = { 'content-type': 'application/json' };
  if (process.env.KUSHBITX_TRIAL_KEY) headers['x-kushbitx-trial-key'] = process.env.KUSHBITX_TRIAL_KEY;
  let doFetch = fetch;
  if (process.env.KUSHBITX_PAYER_KEY) {
    const { x402Client, wrapFetchWithPayment } = await import('@x402/fetch');
    const { registerExactEvmScheme } = await import('@x402/evm/exact/client');
    const { privateKeyToAccount } = await import('viem/accounts');
    const client = new x402Client();
    registerExactEvmScheme(client, { signer: privateKeyToAccount(process.env.KUSHBITX_PAYER_KEY) });
    client.setSpendControls({ maxAmountPerPayment: MAX_PER_CALL });
    doFetch = wrapFetchWithPayment(fetch, client);
  } else if (!process.env.KUSHBITX_TRIAL_KEY) deny('set KUSHBITX_PAYER_KEY (pays 0.001 USDC per check) or KUSHBITX_TRIAL_KEY');
  const response = await doFetch(ENDPOINT, { method: 'POST', headers, body: JSON.stringify({ chain: 'base', address: token }) });
  if (response.status !== 200) deny('Token Risk returned HTTP ' + response.status + (response.status === 402 ? ' (payment needed: trial ended or no payer key)' : ''));
  report = await response.json();
} catch (error) { deny('Token Risk unavailable: ' + String(error?.message || error).slice(0, 120)); }
clearTimeout(timer);

const decision = report?.verdict?.decision;
const flags = (report?.risk?.flags || []).filter(f => ['high', 'critical'].includes(f.severity)).map(f => f.code).slice(0, 5);
if (decision === 'ALLOW') allow();
if (decision === 'WARN' && process.env.KUSHBITX_ALLOW_WARN === '1' && !flags.length) allow();
deny('Token Risk ' + (decision || 'gave no verdict') + ' for ' + token + (flags.length ? ' (' + flags.join(', ') + ')' : '') + '. INCOMPLETE means missing evidence, never "safe".');
