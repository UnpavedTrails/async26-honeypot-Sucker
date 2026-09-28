#!/usr/bin/env node
// ASYNC'26 - attack demo simulator.
//
// Fires scripted, scanner-style traffic at YOUR OWN honeypot so the analysis
// pipeline and dashboard have something realistic to narrate. Only ever point
// this at your own deployment. Requires Node 18+ (built-in fetch), no installs.
//
// Usage:
//   node attack_demo.js https://your-honeypot.onrender.com            # all scenarios
//   node attack_demo.js https://your-honeypot.onrender.com recon      # one scenario
//   TARGET=https://your-honeypot.onrender.com node attack_demo.js stuffing
//
// Scenarios: recon | stuffing | injection | all
//
// Each scenario uses a different User-Agent. The honeypot groups sessions by
// IP + User-Agent, so each one shows up as its own card on the dashboard.

const args = process.argv.slice(2);
const target = (args.find((a) => a.startsWith('http')) || process.env.TARGET || '').replace(/\/+$/, '');
const scenario = args.find((a) => !a.startsWith('http')) || 'all';

if (!target) {
  console.error('Missing target. Example: node attack_demo.js https://your-honeypot.onrender.com');
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (min, max) => min + Math.random() * (max - min);

async function hit(method, path, { ua, body, timeoutMs = 20000 } = {}) {
  const started = Date.now();
  try {
    const res = await fetch(target + path, {
      method,
      headers: {
        'User-Agent': ua,
        ...(body ? { 'Content-Type': 'application/json' } : {})
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs)
    });
    console.log(`  ${method.padEnd(4)} ${path.padEnd(34)} -> ${res.status} (${Date.now() - started}ms)`);
  } catch (err) {
    console.log(`  ${method.padEnd(4)} ${path.padEnd(34)} -> failed: ${err.message}`);
  }
}

// A normal-looking browser visit. Also wakes a sleeping Render free-tier
// instance, and gives the dashboard a harmless session to contrast against.
async function warmup() {
  console.log(`\nWaking target (Render free tier can take up to a minute)...`);
  await hit('GET', '/', {
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36',
    timeoutMs: 90000
  });
}

async function recon() {
  console.log('\n[recon] Automated path discovery');
  const ua = 'Nmap Scripting Engine; https://nmap.org/book/nse.html';
  const paths = [
    '/admin', '/administrator', '/wp-login.php', '/wp-admin/', '/.env', '/.git/config',
    '/phpmyadmin/', '/api/users', '/api/v1/admin', '/backup.zip', '/server-status',
    '/config.json', '/robots.txt', '/login'
  ];
  for (const p of paths) {
    await hit('GET', p, { ua });
    await sleep(jitter(120, 320));
  }
}

async function stuffing() {
  console.log('\n[stuffing] Rapid login attempts with common credentials');
  const ua = 'python-requests/2.31.0';
  const emails = ['admin@example.com', 'root@example.com', 'test@example.com', 'user@example.com', 'info@example.com'];
  const passwords = ['123456', 'password', 'admin123', 'qwerty', 'letmein', 'welcome1'];
  let n = 0;
  for (const email of emails) {
    for (const password of passwords) {
      if (n++ >= 18) return;
      await hit('POST', '/api/auth/login', { ua, body: { email, password } });
      await sleep(jitter(150, 350));
    }
  }
}

async function injection() {
  console.log('\n[injection] Classic injection strings in login fields and query params');
  const ua = 'sqlmap/1.7#stable (https://sqlmap.org)';
  const payloads = [
    { email: "admin' OR '1'='1' --", password: 'x' },
    { email: "' OR 1=1 --", password: 'x' },
    { email: "admin'--", password: 'anything' },
    { email: '<script>alert(1)</script>', password: 'x' },
    { email: '"><img src=x onerror=alert(1)>', password: 'x' }
  ];
  for (const body of payloads) {
    await hit('POST', '/api/auth/login', { ua, body });
    await sleep(jitter(300, 700));
  }
  await hit('GET', '/?file=../../etc/passwd', { ua });
  await sleep(jitter(300, 700));
  await hit('GET', "/search?q=1'%20UNION%20SELECT%20NULL--", { ua });
}

const scenarios = { recon, stuffing, injection };

(async () => {
  console.log(`Target: ${target}`);
  if (scenario !== 'all' && !scenarios[scenario]) {
    console.error(`Unknown scenario "${scenario}". Use: recon | stuffing | injection | all`);
    process.exit(1);
  }

  await warmup();

  const toRun = scenario === 'all' ? Object.keys(scenarios) : [scenario];
  for (let i = 0; i < toRun.length; i++) {
    await scenarios[toRun[i]]();
    if (i < toRun.length - 1) await sleep(4000);
  }

  console.log('\nDone. The analysis service polls every ~10s - watch the dashboard for new session cards.');
})();
