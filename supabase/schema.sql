-- Enable UUID generation extension if not present
create extension if not exists "uuid-ossp";

-- Table for scans
create table scans (
    id uuid primary key default gen_random_uuid(),
    filename text,
    target_url text,
    status text not null default 'queued',
    scanned_files integer not null default 0,
    overall_score integer not null default 100,
    code_security integer not null default 100,
    authentication integer not null default 100,
    api_security integer not null default 100,
    infrastructure integer not null default 100,
    compliance integer not null default 100,
    attack_surface text,
    potential_threats text[],
    risk_matrix text,
    exploitation_scenarios text[],
    mitigation_plan text,
    hardening_recs text[],
    created_at timestamp with time zone not null default timezone('utc'::text, now()),
    user_id uuid references auth.users(id) on delete set null
);

-- Table for findings
create table findings (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references scans(id) on delete cascade,
    name text not null,
    category text not null,
    cwe text not null,
    owasp text not null,
    severity text not null,
    file text not null,
    line integer not null,
    description text not null,
    code_snippet text not null,
    vulnerable_code text not null,
    fix_guidance text not null,
    secure_fix text,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Table for chat messages
create table chat_messages (
    id uuid primary key default gen_random_uuid(),
    session_id uuid not null,
    role text not null, -- 'user' or 'assistant'
    content text not null,
    created_at timestamp with time zone not null default timezone('utc'::text, now()),
    user_id uuid references auth.users(id) on delete set null
);

-- Indexes for performance (joins & CASCADE speed-up)
create index findings_scan_id_idx on findings(scan_id);
create index chat_messages_session_id_idx on chat_messages(session_id);

-- Enable Row Level Security (RLS)
alter table scans enable row level security;
alter table findings enable row level security;
alter table chat_messages enable row level security;

-- RLS Policies
create policy scans_access_policy on scans
    for all
    using (true)
    with check (true);

create policy findings_access_policy on findings
    for all
    using (true)
    with check (true);

create policy chat_messages_access_policy on chat_messages
    for all
    using (true)
    with check (true);
