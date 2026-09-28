# Analysis Service — ASYNC'26

Polls Supabase for unanalyzed honeypot logs, groups them by session, sends
each session's activity to Gemini for classification and plain-English
narration, then writes the result back to the `analysis` table.

## What it does, in order

1. Every `POLL_INTERVAL_MS` (default 10s), query `raw_logs WHERE analyzed = false`.
2. Group the results by `session_id` — one attacker "session" may span several requests.
3. Send each session's requests to Gemini as one sequence (not isolated events), constrained to return exactly: `intent_label`, `severity_score`, `narration`, `recommended_action`.
4. Insert the result into `analysis`.
5. Mark those specific `raw_logs` rows as `analyzed = true`.
6. If anything fails mid-way (network hiccup, rate limit, etc.), those rows are simply left `analyzed = false` and get retried automatically on the next poll — nothing is silently lost.

A session can end up with more than one `analysis` row over time if it sends multiple bursts of activity — that's intentional, and reads well on a dashboard as narration updating live rather than a single final verdict.

## Setup

1. Get a free Gemini API key at **aistudio.google.com** — sign in with a Google account, no credit card needed.
2. `npm install`
3. `cp .env.example .env` and fill in:
   - `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` (same values as the honeypot's `.env`)
   - `GEMINI_API_KEY` from step 1
4. `npm start`

You should immediately see it pick up any logs already sitting in `raw_logs` with `analyzed = false` — including whatever's left over from earlier honeypot testing.

## Verifying it worked

In Supabase's Table Editor:
- `analysis` table should now have new rows with narration text.
- `raw_logs` table: the rows that were just processed should now show `analyzed = true`.

## Notes

- Built on `@google/genai` (the current Gemini SDK — the older `@google/generative-ai` package was deprecated in late 2025, so this avoids building on something already out of date).
- Model: `gemini-2.5-flash` — documented as stable and free-tier; scheduled retirement is well after this hackathon's dates.
- This script needs to be running continuously in its own terminal window alongside the honeypot for logs to actually get analyzed.
