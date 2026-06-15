-- Enable UUID generation extension if not present
create extension if not exists "uuid-ossp";

-- Table for profiles
create table public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    gemini_api_key text,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Table for scans
create table public.scans (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id) on delete cascade,
    project_name text not null,
    source_type text not null, -- 'paste' | 'zip' | 'github'
    status text not null default 'pending', -- 'pending' | 'scanning' | 'done' | 'error'
    overall_score integer,
    projected_score integer,
    grade text,
    raw_code text,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Table for findings
create table public.findings (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references public.scans(id) on delete cascade,
    title text not null,
    description text,
    severity text not null, -- 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
    cvss_score numeric(3,1),
    owasp_category text,
    cwe_id text,
    vulnerable_snippet text,
    secure_fix text,
    fix_recommendation text,
    impact_analysis text,
    attack_narrative text,
    file_path text not null default 'unknown',
    line_number integer not null default 1,
    is_ai_smell boolean not null default false,
    is_fixed boolean not null default false,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Table for IDOR endpoints
create table public.idor_endpoints (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references public.scans(id) on delete cascade,
    endpoint text not null,
    method text not null,
    risk_level text not null, -- 'High' | 'Medium' | 'Low'
    has_auth_check boolean not null default false,
    has_ownership_check boolean not null default false,
    reasoning text,
    line_number integer default 1,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Table for compliance flags
create table public.compliance_flags (
    id uuid primary key default gen_random_uuid(),
    scan_id uuid not null references public.scans(id) on delete cascade,
    framework text, -- 'GDPR' | 'PCI-DSS' | 'SOC2' | 'OWASP ASVS'
    risk_level text, -- 'Critical' | 'High' | 'Medium'
    reason text,
    created_at timestamp with time zone not null default timezone('utc'::text, now())
);

-- Indexes for performance (joins & CASCADE speed-up)
create index findings_scan_id_idx on public.findings(scan_id);
create index idor_endpoints_scan_id_idx on public.idor_endpoints(scan_id);
create index compliance_flags_scan_id_idx on public.compliance_flags(scan_id);

-- Enable Row Level Security (RLS)
alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.findings enable row level security;
alter table public.idor_endpoints enable row level security;
alter table public.compliance_flags enable row level security;

-- RLS Policies
create policy profiles_user_policy on public.profiles
    for all using (auth.uid() = id) with check (auth.uid() = id);

create policy scans_user_policy on public.scans
    for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy findings_user_policy on public.findings
    for all using (exists (
        select 1 from public.scans where scans.id = findings.scan_id and scans.user_id = auth.uid()
    ));

create policy idor_user_policy on public.idor_endpoints
    for all using (exists (
        select 1 from public.scans where scans.id = idor_endpoints.scan_id and scans.user_id = auth.uid()
    ));

create policy compliance_user_policy on public.compliance_flags
    for all using (exists (
        select 1 from public.scans where scans.id = compliance_flags.scan_id and scans.user_id = auth.uid()
    ));

-- Trigger to create profile on signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id)
  values (new.id);
  return new;
end;
$$ language plpgsql security definer;

create or replace trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
