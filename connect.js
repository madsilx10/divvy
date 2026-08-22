const fs = require('fs');
const path = require('path');
const readline = require('readline');

// ====== CONFIG ======
const ACCOUNTS_FILE = path.join(__dirname, 'akun.txt');
const RESULTS_FILE = path.join(__dirname, 'results.json');

// Bearer token publik yang dipakai X web client (sama untuk semua akun, bukan rahasia per-user)
const X_BEARER = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA';

const UA = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36';

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

async function processAccount(account, index) {
  const label = `[Akun ${index + 1}]`;
  const jar = new CookieJar();

  try {
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

    const location = callbackRes.headers.get('location');
    if (callbackRes.status >= 300 && callbackRes.status < 400 && location) {
      console.log(`${label} SUKSES ✅ (redirect ${callbackRes.status} -> ${location})`);
      return { account: `${account.auth_token.slice(0, 8)}...`, status: 'success', redirectTo: location };
    }

    console.log(`${label} SUKSES ✅`, callbackRes.status, JSON.stringify(callbackRes.data).slice(0, 200));
    return { account: `${account.auth_token.slice(0, 8)}...`, status: 'success', response: callbackRes.data };
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
  console.log(`Ketemu ${accounts.length} akun di akun.txt\n`);

  if (accounts.length === 0) {
    console.log('Gak ada akun valid di akun.txt, cek formatnya.');
    return;
  }

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
