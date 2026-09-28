create extension if not exists pgcrypto;

create table if not exists raw_logs (
  id            uuid primary key default gen_random_uuid(),
  session_id    text not null,
  ip_address    text not null,
  timestamp     timestamptz default now(),
  method        text,
  path          text,
  headers       jsonb,
  body          jsonb,
  user_agent    text,
  analyzed      boolean default false
);

create table if not exists analysis (
  id                  uuid primary key default gen_random_uuid(),
  session_id          text not null,
  created_at          timestamptz default now(),
  intent_label        text,
  severity_score      int,
  narration           text,
  recommended_action  text
);

-- Row Level Security matters here for the `anon` key specifically, since
-- that's the key that gets exposed in browser JS (used later by the
-- dashboard frontend). The honeypot backend and analysis service instead
-- use the SERVICE ROLE key, which bypasses RLS entirely - that's fine
-- because it's a secret that only lives server-side in your own .env files
-- and is never sent to a browser or exposed to anyone hitting the honeypot's
-- HTTP endpoints.
alter table raw_logs enable row level security;
alter table analysis enable row level security;

-- Dashboard frontend (anon key) can only ever read - never insert/update/delete.
create policy "dashboard read raw_logs"
  on raw_logs for select
  to anon
  using (true);

create policy "dashboard read analysis"
  on analysis for select
  to anon
  using (true);

-- No insert/update/delete policies exist for `anon` above, so those actions
-- are denied by default once RLS is enabled - even if the public anon key
-- leaked, it could not write to either table.

-- Realtime does NOT turn on automatically just because a table exists -
-- each table has to be explicitly added to the realtime publication, or
-- the dashboard's live subscription will silently never fire (initial load
-- still works fine, it just never updates without a manual refresh).
-- If you already ran the block above, just run these two lines on their own.
alter publication supabase_realtime add table raw_logs;
alter publication supabase_realtime add table analysis;
