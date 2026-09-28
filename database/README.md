# Database Setup — Supabase

Nothing to install locally. Supabase is a hosted Postgres database — you just
create a free project through their website and get credentials back.

## Steps

1. Go to https://supabase.com and sign up (or log in).
2. Click **New Project**. Pick any name/region, set a database password (save it somewhere — you likely won't need it directly, but keep it).
3. Once the project finishes provisioning, go to **Project Settings → API**. Note down two values:
   - **Project URL** (`SUPABASE_URL`)
   - **service_role key** (`SUPABASE_SERVICE_ROLE_KEY`) — under "Project API keys." This is secret; never commit it or expose it to a frontend.
   - You'll also eventually need the **anon/public key** for the dashboard (Contract E) — grab that too while you're here, but that one's safe to expose in browser code.
4. Go to the **SQL Editor** (left sidebar), paste in the contents of `schema.sql` from this folder, and run it. This creates the `raw_logs` and `analysis` tables plus the RLS policies.
5. Copy `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` into `honeypot/.env` (and later, the analysis service's `.env`).

## What lives here

- `schema.sql` — the single source of truth for the DB shape. Every service (honeypot, analysis service, dashboard) is built against this exact schema, so if it ever needs to change, change it here first and re-run it in Supabase's SQL editor.

## Which key goes where

| Component | Key to use | Why |
|---|---|---|
| Honeypot backend | `service_role` | Trusted server-side code, key never leaves your `.env` |
| Analysis service | `service_role` | Needs to read + update `raw_logs` and write `analysis` |
| Dashboard frontend | `anon` (public) | Exposed in browser JS — restricted to read-only via RLS |
