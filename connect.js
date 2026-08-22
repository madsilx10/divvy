const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// ====== CONFIG ======
const ACCOUNTS_FILE = path.join(__dirname, 'akun.txt');
const WALLET_FILE = path.join(__dirname, 'wallet.txt');
const RESULTS_FILE = path.join(__dirname, 'results.json');
const BASE = 'https://register.divvy.bet';
const REF_CODE = 'mirzaeaj'; // dari link https://register.divvy.bet/?ref=mirzaeaj

// server function IDs ini hash dari build frontend divvy.bet, bisa berubah kalo mereka redeploy
const POW_FN_ID = 'fda52486cac50b30ddb4ed62ec45ed8fdaf8d6c1930bbcfb356f8a7becec232c';
const WALLET_FN_ID = '355f8109965dbc60826e55d5fc2947a7175a6982988b27ca4837e0d3afc114c3';

// Bearer token publik yang dipakai X web client (sama untuk semua akun, bukan rahasia per-user)
const X_BEARER = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA';

const UA = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36';

// ====== Base58 manual (buat decode private key Solana, no depend ke package bs58) ======
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`karakter base58 invalid: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  let bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  for (const ch of str) {
    if (ch === '1') bytes.unshift(0); else break;
  }
  return Buffer.from(bytes);
}
function base58Encode(buf) {
  let num = 0n;
  for (const b of buf) num = num * 256n + BigInt(b);
  let out = '';
  while (num > 0n) {
    out = B58_ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  for (const b of buf) {
    if (b === 0) out = '1' + out; else break;
  }
  return out || '1';
}

// Secret key Solana (format umum export Phantom dkk): 64 byte = seed(32) + pubkey(32).
// Jadi address wallet bisa langsung diturunin dari 32 byte terakhir, gaperlu library ed25519.
function pubkeyFromPrivateKey(privKeyBase58) {
  const secretKey = base58Decode(privKeyBase58.trim());
  if (secretKey.length !== 64) {
    throw new Error(`private key harus 64 byte (secret key Solana), ketemu ${secretKey.length} byte`);
  }
  const pubKeyBytes = secretKey.subarray(32, 64);
  return base58Encode(pubKeyBytes);
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ====== Simple per-account cookie jar (fetch gak handle cookie otomatis) ======
class CookieJar {
  constructor() { this.jar = new Map(); } // key: "domain|name" -> value

  static domainFromUrl(url) { return new URL(url).hostname; }

  absorb(res, url) {
    const domain = CookieJar.domainFromUrl(url);
    let setCookies = [];
    if (typeof res.headers.getSetCookie === 'function') {
      setCookies = res.headers.getSetCookie();
    } else {
      const single = res.headers.get('set-cookie');
      if (single) setCookies = [single];
    }
    for (const raw of setCookies) {
      const first = raw.split(';')[0];
      const eq = first.indexOf('=');
      if (eq === -1) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      this.jar.set(`${domain}|${name}`, value);
    }
  }

  set(domain, name, value) { this.jar.set(`${domain}|${name}`, value); }

  cookieHeaderFor(url) {
    const domain = CookieJar.domainFromUrl(url);
    const pairs = [];
    for (const [key, value] of this.jar.entries()) {
      const [d, name] = key.split('|');
      if (domain === d || domain.endsWith(`.${d}`) || d.endsWith(`.${domain}`)) {
        pairs.push(`${name}=${value}`);
      }
    }
    return pairs.join('; ');
  }
}

async function req(jar, url, { method = 'GET', params, headers = {}, body } = {}) {
  const u = new URL(url);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) u.searchParams.set(k, v);
    });
  }
  const cookieHeader = jar.cookieHeaderFor(u.toString());
  const finalHeaders = {
    'User-Agent': UA,
    ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    ...headers,
  };

  const res = await fetch(u.toString(), { method, headers: finalHeaders, body, redirect: 'manual' });
  jar.absorb(res, u.toString());

  let data = null;
  const text = await res.text();
  try { data = JSON.parse(text); } catch { data = text; }

  return { status: res.status, headers: res.headers, data };
}

// ====== Load akun.txt (blok pisah blank line: auth_token baris 1, ct0 baris 2) ======
function loadAccounts() {
  const raw = fs.readFileSync(ACCOUNTS_FILE, 'utf-8').replace(/\r\n/g, '\n');
  const blocks = raw.split(/\n\s*\n/).map((b) => b.trim()).filter(Boolean);
  return blocks.map((b) => {
    const lines = b.split('\n').map((l) => l.trim()).filter(Boolean);
    return { auth_token: lines[0], ct0: lines[1] };
  }).filter((a) => a.auth_token && a.ct0);
}

// ====== Load wallet.txt (satu private key base58 per baris) ======
function loadWallets() {
  if (!fs.existsSync(WALLET_FILE)) return [];
  return fs.readFileSync(WALLET_FILE, 'utf-8')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

// ====== Parser buat format "tss-framed" (t=type tag, i=id, p={k:keys,v:values}) ======
// t:0=number, t:1=string, t:2=special(undefined/null/bool marker, diabaikan), t:10=object, t:11=array
function parseTss(node) {
  if (node === null || typeof node !== 'object') return node;
  switch (node.t) {
    case 0:
    case 1:
      return node.s;
    case 2:
      return undefined;
    case 10: {
      const obj = {};
      const keys = node.p?.k || [];
      const vals = node.p?.v || [];
      keys.forEach((k, idx) => { obj[k] = parseTss(vals[idx]); });
      return obj;
    }
    case 11:
      return (node.p?.v || []).map(parseTss);
    default:
      return node.s;
  }
}

function buildWalletPayload(walletAddress, token, solution, referrerCode) {
  const referrerNode = referrerCode
    ? { t: 1, s: referrerCode }
    : { t: 2, s: 0 };

  return JSON.stringify({
    t: {
      t: 10,
      i: 0,
      p: {
        k: ['data'],
        v: [{
          t: 10,
          i: 1,
          p: {
            k: ['walletAddress', 'referrer', 'website', 'challenge'],
            v: [
              { t: 1, s: walletAddress },
              referrerNode,
              { t: 1, s: '' }, // website: honeypot field, harus kosong
              {
                t: 10,
                i: 2,
                p: {
                  k: ['token', 'solution'],
                  v: [
                    { t: 1, s: token },
                    { t: 0, s: solution },
                  ],
                },
                o: 0,
              },
            ],
          },
          o: 0,
        }],
      },
      o: 0,
    },
    f: 63,
    m: [],
  });
}

// ====== Proof-of-work: cari counter dimana SHA256("nonce:counter") punya N leading zero bit ======
function sha256(str) { return crypto.createHash('sha256').update(str).digest(); }

function hasLeadingZeroBits(buf, bits) {
  const fullBytes = Math.floor(bits / 8);
  for (let i = 0; i < fullBytes; i += 1) if (buf[i] !== 0) return false;
  const rem = bits % 8;
  if (rem === 0) return true;
  const b = buf[fullBytes];
  return b !== undefined && (b >> (8 - rem)) === 0;
}

function solvePow(nonce, difficulty) {
  for (let i = 0; i <= 4294967295; i += 1) {
    if (hasLeadingZeroBits(sha256(`${nonce}:${i}`), difficulty)) return i;
  }
  throw new Error('PoW solution gak ketemu (range habis)');
}

async function connectWallet(jar, label, walletAddress) {
  console.log(`${label} minta PoW challenge...`);
  const powRes = await req(jar, `${BASE}/_serverFn/${POW_FN_ID}`, {
    method: 'POST',
    headers: {
      Accept: 'application/x-tss-framed, application/x-ndjson, application/json',
      'Content-Type': 'application/json',
      'X-Tsr-Serverfn': 'true',
      Origin: BASE,
      Referer: `${BASE}/`,
    },
    body: '{}',
  });

  const challenge = parseTss(powRes.data)?.result;
  if (!challenge?.nonce) {
    throw new Error(`gagal ambil pow challenge: ${JSON.stringify(powRes.data).slice(0, 300)}`);
  }

  console.log(`${label} solve PoW (difficulty ${challenge.difficulty})...`);
  const solution = solvePow(challenge.nonce, challenge.difficulty);

  console.log(`${label} submit wallet address...`);
  const walletRes = await req(jar, `${BASE}/_serverFn/${WALLET_FN_ID}`, {
    method: 'POST',
    headers: {
      Accept: 'application/x-tss-framed, application/x-ndjson, application/json',
      'Content-Type': 'application/json',
      'X-Tsr-Serverfn': 'true',
      Origin: BASE,
      Referer: `${BASE}/`,
    },
    body: buildWalletPayload(walletAddress, challenge.token, solution, REF_CODE),
  });

  const result = parseTss(walletRes.data)?.result;
  if (!result?.walletAddress) {
    throw new Error(`wallet connect gagal: ${JSON.stringify(walletRes.data).slice(0, 300)}`);
  }
  return result;
}

async function processAccount(account, index) {
  const label = `[Akun ${index + 1}]`;
  const jar = new CookieJar();

  try {
    console.log(`${label} set referral cookie...`);
    await req(jar, `${BASE}/?ref=${REF_CODE}`, {
      headers: { Referer: `${BASE}/` },
    });

    console.log(`${label} mulai flow (GET /api/auth/x/start)...`);
    const startRes = await req(jar, 'https://register.divvy.bet/api/auth/x/start', {
      headers: { Referer: 'https://register.divvy.bet/' },
    });

    // start ini 302 langsung ke x.com/i/oauth2/authorize (bukan JSON kayak memebitcoin)
    const authorizeUrlStr = startRes.headers.get('location');
    if (!authorizeUrlStr) {
      throw new Error(`start gagal, no Location header: ${startRes.status} ${JSON.stringify(startRes.data).slice(0, 200)}`);
    }

    const authorizeUrl = new URL(authorizeUrlStr);
    const client_id = authorizeUrl.searchParams.get('client_id');
    const code_challenge = authorizeUrl.searchParams.get('code_challenge');
    const code_challenge_method = authorizeUrl.searchParams.get('code_challenge_method');
    const redirect_uri = authorizeUrl.searchParams.get('redirect_uri');
    const scope = authorizeUrl.searchParams.get('scope');
    const state = authorizeUrl.searchParams.get('state');
    if (!client_id) throw new Error(`gagal parse authorizeUrl: ${authorizeUrlStr}`);

    const authorizeParams = {
      client_id,
      code_challenge,
      code_challenge_method: code_challenge_method || 'S256',
      redirect_uri,
      response_type: 'code',
      scope,
      state,
    };

    jar.set('x.com', 'auth_token', account.auth_token);
    jar.set('x.com', 'ct0', account.ct0);

    const xHeaders = {
      Authorization: `Bearer ${X_BEARER}`,
      'x-csrf-token': account.ct0,
      'x-twitter-auth-type': 'OAuth2Session',
      'x-twitter-active-user': 'yes',
      'x-twitter-client-language': 'id',
      'Content-Type': 'application/json',
    };

    console.log(`${label} request authorize (GET)...`);
    const authRes = await req(jar, 'https://x.com/i/api/2/oauth2/authorize', {
      params: authorizeParams,
      headers: xHeaders,
    });

    const authCode = authRes.data && authRes.data.auth_code;
    if (!authCode) {
      throw new Error(`gagal ambil auth_code (mungkin auth_token/ct0 expired): ${JSON.stringify(authRes.data)}`);
    }

    console.log(`${label} approve authorize (POST)...`);
    const approveRes = await req(jar, 'https://x.com/i/api/2/oauth2/authorize', {
      method: 'POST',
      headers: {
        ...xHeaders,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ approval: 'true', code: authCode }).toString(),
    });

    let finalCode; let finalState;
    const approveData = approveRes.data;
    if (approveData && approveData.redirect_uri) {
      const u = new URL(approveData.redirect_uri);
      finalCode = u.searchParams.get('code');
      finalState = u.searchParams.get('state');
    } else if (approveRes.headers.get('location')) {
      const u = new URL(approveRes.headers.get('location'));
      finalCode = u.searchParams.get('code');
      finalState = u.searchParams.get('state');
    } else if (approveData && approveData.code) {
      finalCode = approveData.code;
      finalState = approveData.state || state;
    }

    if (!finalCode) {
      throw new Error(`gak nemu code final di response approve, cek manual: ${JSON.stringify(approveData)}`);
    }

    console.log(`${label} hit callback...`);
    // callback butuh cookie divvy_hilo_x_oauth (di-set pas step /start), jar udah otomatis bawa
    const callbackRes = await req(jar, 'https://register.divvy.bet/api/auth/x/callback', {
      params: { code: finalCode, state: finalState },
      headers: { Referer: 'https://x.com/' },
    });

    const isRedirectOk = callbackRes.status >= 300 && callbackRes.status < 400;
    const isJsonOk = callbackRes.status === 200 && callbackRes.data && !callbackRes.data.error;
    if (!isRedirectOk && !isJsonOk) {
      throw new Error(`callback gagal, status=${callbackRes.status}: ${JSON.stringify(callbackRes.data).slice(0, 300)}`);
    }

    console.log(`${label} X connected ✅`);

    if (!account.wallet) {
      console.log(`${label} gaada wallet address di akun.txt, skip step connect wallet.`);
      return { account: `${account.auth_token.slice(0, 8)}...`, status: 'success_no_wallet' };
    }

    const walletResult = await connectWallet(jar, label, account.wallet);
    console.log(`${label} WALLET CONNECTED ✅ regNo=${walletResult.registrationNumber} dvy=${walletResult.dvyAwarded}`);

    return {
      account: `${account.auth_token.slice(0, 8)}...`,
      status: 'success',
      xUsername: walletResult.xUsername,
      walletAddress: walletResult.walletAddress,
      registrationNumber: walletResult.registrationNumber,
      dvyAwarded: walletResult.dvyAwarded,
    };
  } catch (err) {
    console.log(`${label} GAGAL ❌ ${err.message}`);
    return { account: `${account.auth_token.slice(0, 8)}...`, status: 'failed', error: err.message };
  }
}

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function runBatch(accounts, indices) {
  const results = [];
  for (let n = 0; n < indices.length; n += 1) {
    const i = indices[n];
    const res = await processAccount(accounts[i], i);
    results.push(res);
    if (n < indices.length - 1) {
      await sleep(2000 + Math.random() * 2000);
    }
  }
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
  const ok = results.filter((r) => r.status === 'success').length;
  console.log(`\nSelesai: ${ok}/${results.length} berhasil. Detail di results.json`);
}

(async () => {
  const accounts = loadAccounts();
  const privKeys = loadWallets();
  console.log(`Ketemu ${accounts.length} akun di akun.txt, ${privKeys.length} privkey di wallet.txt\n`);

  if (accounts.length === 0) {
    console.log('Gak ada akun valid di akun.txt, cek formatnya.');
    return;
  }

  if (privKeys.length > 0 && privKeys.length !== accounts.length) {
    console.log(`⚠️  Jumlah akun (${accounts.length}) dan wallet (${privKeys.length}) beda. Dipasangin berdasarkan urutan baris, sisanya skip wallet connect.\n`);
  }

  // pasangin akun[i] <-> wallet.txt baris ke-i (by index), derive address dari privkey
  accounts.forEach((acc, i) => {
    const priv = privKeys[i];
    if (!priv) return;
    try {
      acc.walletPriv = priv;
      acc.wallet = pubkeyFromPrivateKey(priv);
    } catch (err) {
      console.log(`[Akun ${i + 1}] ⚠️ privkey baris ${i + 1} gagal diparse: ${err.message}`);
    }
  });

  console.log('Pilih mode:');
  console.log('  1. Satu akun');
  console.log('  2. Semua akun');
  console.log('  3. Range (dari nomor X sampai akhir)');
  const mode = await ask('Masukin pilihan (1/2/3): ');

  let indices;
  if (mode === '1') {
    const numStr = await ask(`Nomor akun (1-${accounts.length}): `);
    const num = parseInt(numStr, 10);
    if (Number.isNaN(num) || num < 1 || num > accounts.length) {
      console.log('Nomor gak valid.');
      return;
    }
    indices = [num - 1];
  } else if (mode === '2') {
    indices = accounts.map((_, i) => i);
  } else if (mode === '3') {
    const numStr = await ask(`Mulai dari akun nomor berapa (1-${accounts.length}): `);
    const start = parseInt(numStr, 10);
    if (Number.isNaN(start) || start < 1 || start > accounts.length) {
      console.log('Nomor gak valid.');
      return;
    }
    indices = accounts.map((_, i) => i).slice(start - 1);
  } else {
    console.log('Pilihan gak valid.');
    return;
  }

  console.log(`\nAkan proses ${indices.length} akun: [${indices.map((i) => i + 1).join(', ')}]\n`);
  await runBatch(accounts, indices);
})();
