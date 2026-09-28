require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client uses the SERVICE ROLE key - a secret, trusted, server-side
// credential. It lives only in .env, never reaches the browser, and an
// attacker hitting this server's routes never sees it or touches Supabase
// directly - they only ever interact with the HTTP layer below.
//
// If env vars aren't set yet, we don't crash - we just fall back to local
// file logging so you can run and test this before Supabase is wired up.
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
} else {
  console.warn(
    '[warning] SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set - ' +
    'logging to local logs.jsonl only, Supabase writes are skipped.'
  );
}

app.set('trust proxy', true);

const LOCAL_LOG_FILE = path.join(__dirname, 'logs.jsonl');

// --- Step 1: capture the raw request body ourselves, for every request.
// We deliberately do NOT use express.json()/express.urlencoded() - those
// throw on malformed bodies, which would crash logging for exactly the kind
// of garbage/malformed input a real attacker sends. Manual capture means
// logging never fails, no matter what's in the request.
app.use((req, res, next) => {
  let data = '';
  req.on('data', (chunk) => { data += chunk; });
  req.on('end', () => {
    req.rawBody = data;
    try {
      req.parsedBody = data ? JSON.parse(data) : {};
    } catch (err) {
      req.parsedBody = data; // not JSON - keep as raw string, still gets logged
    }
    next();
  });
  req.on('error', () => {
    req.rawBody = '';
    req.parsedBody = {};
    next();
  });
});

// --- Step 2: log every single request, no filtering, no validation.
app.use((req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const sessionId = crypto
    .createHash('sha256')
    .update(ip + userAgent)
    .digest('hex')
    .slice(0, 16);

  const logEntry = {
    session_id: sessionId,
    ip_address: ip,
    method: req.method,
    path: req.originalUrl,
    headers: req.headers,
    body: req.parsedBody,
    user_agent: userAgent
  };

  // Local backup copy - fire and forget, never blocks the response.
  // Useful for debugging before Supabase is set up, and as demo-day insurance.
  fs.appendFile(
    LOCAL_LOG_FILE,
    JSON.stringify({ ...logEntry, timestamp: new Date().toISOString() }) + '\n',
    () => {}
  );

  // Supabase insert - also fire and forget. A slow/failed DB write should
  // never be the reason the honeypot looks broken or slow to a visitor.
  if (supabase) {
    supabase
      .from('raw_logs')
      .insert([logEntry])
      .then(({ error }) => {
        if (error) console.error('[supabase insert error]', error.message);
      });
  }

  next();
});

// --- Step 3: serve the decoy frontend as static files (public/index.html).
app.use(express.static(path.join(__dirname, 'public')));

// --- Step 4: the fake login endpoint. Always generic, never reveals anything.
app.post('/api/auth/login', (req, res) => {
  setTimeout(() => {
    res.status(401).json({ error: 'Invalid email or password' });
  }, 300);
});

// --- Step 5: catch-all for literally everything else - any path, any method.
// Looks like a plain, unremarkable server: no stack traces, no hints.
app.all('*', (req, res) => {
  res.status(404).type('text').send(`Cannot ${req.method} ${req.path}`);
});

app.listen(PORT, () => {
  console.log(`Honeypot listening on http://localhost:${PORT}`);
});
