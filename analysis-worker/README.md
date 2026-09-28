# Analysis Worker — ASYNC'26

Cloud version of `analysis-service/`. A Cloudflare Worker with a Cron Trigger
that runs once a minute, so nothing has to stay running on your laptop.

Each run reads unanalyzed `raw_logs` rows, groups them by session, has Gemini
classify and narrate each session (structured JSON output), writes the result
to `analysis`, and marks exactly those rows `analyzed = true`. Failures leave
rows unanalyzed, so the next run retries them.

## Deploy

From this folder:

1. `npx wrangler login` (opens a browser; use the same Cloudflare account as your Pages site)
2. `npx wrangler deploy`
3. Add the three secrets (values are hidden as you paste them):
   - `npx wrangler secret put SUPABASE_URL`
   - `npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY`
   - `npx wrangler secret put GEMINI_API_KEY`
4. Stop the local `analysis-service` if it's running. Two analyzers at once
   will both grab the same rows and create duplicate analyses.
5. Watch it: `npx wrangler tail`

Secrets live in Cloudflare, never in this repo.

## Behavior and limits

- Runs every minute, so narration lags a live attack by up to about a minute
  (the local service polls every 10 seconds).
- Analyzes at most 3 sessions and 40 requests per session per run. Extra
  sessions wait for the next run. This keeps each run inside the free plan's
  50-subrequest limit and stops a flood of junk sessions from burning Gemini
  quota.
- Model chain: `gemini-3.8-flash`, then `gemini-3-flash-preview`, then
  `gemini-3.1-flash-lite` if the previous one is overloaded.
- Request contents are truncated and the prompt tells the model to treat them
  as untrusted data, since attacker-controlled text ends up in the prompt.

## Troubleshooting

- `[config] missing secret ...` in the logs: run the matching
  `wrangler secret put` command. Expected for the first minute after deploy.
- `[analysis error] ... Gemini ... 503`: Google-side overload; it retries on
  the next run automatically.
- Nothing in the logs: cron can take up to a minute to fire after deploy.
