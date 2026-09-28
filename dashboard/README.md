# Dashboard — ASYNC'26

A single static HTML file. No npm install, no build step, no local server
required — it only talks to Supabase over HTTPS, so you can open it directly
in a browser.

## What it does

- **Contract E** — loads existing `raw_logs` and `analysis` rows on open, then
  subscribes to Supabase Realtime so new activity appears automatically,
  grouped into session cards sorted by most recent activity.
- **Contract F** — each session card has a "Download report" button that
  formats that session's analysis + raw request log as a Markdown file and
  triggers a browser download. No server involved — it's built entirely from
  data already sitting in the browser.

## Setup

1. **Run the realtime setup SQL** (if you haven't already) — see the two
   `alter publication` lines added to `database/schema.sql`. Without this,
   the dashboard loads existing data fine but silently never updates live.
2. Open `index.html` in a text editor and fill in the config block near the
   top of the `<script>` section:
   ```js
   const SUPABASE_URL = 'YOUR_SUPABASE_URL';
   const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
   ```
   Use the **anon (public) key** here, not the service role key — find it in
   Supabase → Project Settings → API. This key is safe to expose; RLS
   restricts it to read-only on both tables.
3. Open `index.html` in a browser (double-click works, or serve it however
   you like).

## Verifying it works

- On open, it should immediately show any sessions already sitting in the
  database from earlier testing.
- Trigger the honeypot again (submit the login form, or run the attack
  script) and watch a session card update or a new one appear within a
  couple of seconds — no page refresh needed.
- Click "Download report" on any session and confirm a `.md` file downloads
  with that session's narration and raw request log.

## Design notes

- Dark, data-dense layout deliberately leaning into a security-monitoring
  tool feel rather than a generic dashboard template.
- Severity is shown as a 5-segment meter (color shifts calm → caution →
  danger) rather than a plain number, so it reads at a glance.
- All attacker-controlled data (paths, request bodies, user agents) is
  HTML-escaped before rendering — this dashboard displays raw honeypot input,
  so it has to defend against its own data the same way any real system
  handling untrusted input would.
