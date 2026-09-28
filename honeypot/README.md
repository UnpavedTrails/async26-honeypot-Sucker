# Honeypot Backend — ASYNC'26

A single Express server that:
1. Serves the decoy login page (`public/index.html`)
2. Logs **every** request it receives — any path, any method, any body, valid or malformed — to Supabase, plus a local `logs.jsonl` backup

One folder, one command to run.

## Setup

1. `npm install`
2. In your Supabase project's SQL editor, run `supabase/schema.sql` — creates the `raw_logs` and `analysis` tables plus RLS policies.
3. `cp .env.example .env` and fill in your Supabase project URL and **service role key** (found in Supabase dashboard → Project Settings → API).
4. `npm start`
5. Visit `http://localhost:3000` to see the decoy login page.

You can run this immediately without Supabase configured — it'll log to `logs.jsonl` only and print a warning, so you can test the frontend/logging behavior before Supabase is wired up.

## What gets logged

Every request — IP, method, path, headers, body, user-agent, timestamp — is written to `raw_logs`, grouped into sessions via a hash of IP + User-Agent. Nothing is filtered or validated; malformed or garbage input is logged exactly as received, since that's the point of a honeypot.

## Security note

This backend holds the Supabase **service role key** — a secret, trusted credential. It lives only in `.env` (never committed, never sent to the browser) and is never exposed to anyone hitting the honeypot's HTTP endpoints. They only ever interact with the routes in `server.js`, never with Supabase directly.

## Next step

Point your attack script at `http://<this-machine's-local-IP>:3000` and confirm requests show up in `logs.jsonl` and (once configured) the `raw_logs` table in Supabase.
