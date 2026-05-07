-- ═══════════════════════════════════════════════════════════════════════
--  BetterMark v4.0 — Supabase Database Setup
--  Run this entire script in your Supabase SQL Editor (one shot).
--  Project: https://supabase.com → SQL Editor → New Query → Paste → Run
-- ═══════════════════════════════════════════════════════════════════════

-- ── 1. EXTENSIONS ─────────────────────────────────────────────────────
-- uuid_generate_v4() for IDs (already enabled on most Supabase projects,
-- but running it here is safe / idempotent)
create extension if not exists "uuid-ossp";


-- ── 2. PROFILES TABLE ─────────────────────────────────────────────────
-- One row per authenticated user. Linked to auth.users via id (UUID).
-- "role" column drives admin vs. regular user access in the app.
-- Supabase Auth handles password hashing, sessions, and JWTs.
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text,                          -- denormalized for easy display
  display_name  text not null default '',
  role          text not null default 'user'
                  check (role in ('admin', 'user')),
  status        text not null default 'active'
                  check (status in ('active', 'suspended')),
  avatar_color  int  not null default 0,       -- index into avatar gradient array
  created_at    timestamptz not null default now(),
  last_sign_in  timestamptz
);

comment on table public.profiles is
  'Extended user data. Linked 1-to-1 with auth.users.';


-- ── 3. FOLDERS TABLE ──────────────────────────────────────────────────
create table if not exists public.folders (
  id         uuid primary key default uuid_generate_v4(),
  owner_id   uuid not null references auth.users(id) on delete cascade,
  name       text not null check (char_length(name) between 1 and 60),
  color      text not null default '#00f5ff',
  emoji      text not null default '📁',
  created_at timestamptz not null default now()
);

comment on table public.folders is
  'Bookmark folders. Isolated per user via RLS on owner_id.';


-- ── 4. BOOKMARKS TABLE ────────────────────────────────────────────────
create table if not exists public.bookmarks (
  id          uuid primary key default uuid_generate_v4(),
  owner_id    uuid not null references auth.users(id) on delete cascade,
  folder_id   uuid references public.folders(id) on delete set null,
  url         text not null check (char_length(url) between 1 and 2000),
  title       text not null check (char_length(title) between 1 and 200),
  description text check (char_length(description) <= 1000),
  category    text not null default 'other'
                check (category in ('article','video','tool','reference','newsletter','blog','other')),
  tags        text[] not null default '{}',
  emoji       text not null default '🌟',
  image_url   text check (char_length(image_url) <= 2000),
  is_favorite boolean not null default false,
  is_shared   boolean not null default false,
  is_deleted  boolean not null default false,
  -- Reading list fields
  in_reading_list     boolean not null default false,
  reading_type        text check (reading_type in ('article','newsletter','blog')),
  reading_status      text default 'unread'
                        check (reading_status in ('unread','reading','finished')),
  reading_progress    int  default 0 check (reading_progress between 0 and 100),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

comment on table public.bookmarks is
  'All bookmarks. Isolated per user via RLS on owner_id.';

-- Index for common queries
create index if not exists bookmarks_owner_idx     on public.bookmarks(owner_id);
create index if not exists bookmarks_folder_idx    on public.bookmarks(folder_id);
create index if not exists bookmarks_deleted_idx   on public.bookmarks(owner_id, is_deleted);
create index if not exists bookmarks_reading_idx   on public.bookmarks(owner_id, in_reading_list);
create index if not exists bookmarks_category_idx  on public.bookmarks(owner_id, category);


-- ── 5. AUTO-UPDATE updated_at ─────────────────────────────────────────
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists bookmarks_set_updated_at on public.bookmarks;
create trigger bookmarks_set_updated_at
  before update on public.bookmarks
  for each row execute function public.set_updated_at();


-- ── 6. AUTO-CREATE PROFILE ON SIGN-UP ────────────────────────────────
-- Fires whenever a new user signs up via Supabase Auth.
-- Copies email and creates the profile row automatically.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  user_count int;
begin
  -- Count existing users to determine if this is the very first one
  select count(*) into user_count from public.profiles;

  insert into public.profiles (id, email, display_name, role, avatar_color)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1)),
    -- First user gets admin role automatically
    case when user_count = 0 then 'admin' else 'user' end,
    (ascii(coalesce(new.email, 'a')) % 4)   -- deterministic avatar color 0-3
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ── 7. ROW LEVEL SECURITY ─────────────────────────────────────────────
-- Enforces data isolation at the database level.
-- Even if app code is compromised, one user cannot see another's data.

-- profiles
alter table public.profiles enable row level security;

create policy "users_see_own_profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "users_update_own_profile"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Admin can see all profiles (needed for user management panel)
create policy "admin_see_all_profiles"
  on public.profiles for select
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.role = 'admin'
    )
  );

-- Admin can update any profile (suspend, change role)
create policy "admin_update_any_profile"
  on public.profiles for update
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.role = 'admin'
    )
  );

-- Admin can delete profiles
create policy "admin_delete_profile"
  on public.profiles for delete
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.role = 'admin'
    )
  );

-- folders
alter table public.folders enable row level security;

create policy "users_crud_own_folders"
  on public.folders for all
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

-- bookmarks
alter table public.bookmarks enable row level security;

create policy "users_crud_own_bookmarks"
  on public.bookmarks for all
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);


-- ── 8. ADMIN HELPER FUNCTIONS ─────────────────────────────────────────
-- These run with SECURITY DEFINER so admins can manage users without
-- bypassing RLS — the function itself validates the caller's role.

-- Get all profiles (admin only)
create or replace function public.admin_get_all_profiles()
returns setof public.profiles language plpgsql security definer as $$
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'Unauthorized: admin role required';
  end if;
  return query select * from public.profiles order by created_at asc;
end;
$$;

-- Suspend / activate a user (admin only)
create or replace function public.admin_set_user_status(target_id uuid, new_status text)
returns void language plpgsql security definer as $$
declare
  admin_count int;
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'Unauthorized: admin role required';
  end if;
  if new_status not in ('active', 'suspended') then
    raise exception 'Invalid status: must be active or suspended';
  end if;
  -- Cannot suspend yourself
  if target_id = auth.uid() then
    raise exception 'Cannot suspend your own account';
  end if;
  update public.profiles set status = new_status where id = target_id;
end;
$$;

-- Change a user's role (admin only)
create or replace function public.admin_set_user_role(target_id uuid, new_role text)
returns void language plpgsql security definer as $$
declare
  admin_count int;
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'Unauthorized: admin role required';
  end if;
  if new_role not in ('admin', 'user') then
    raise exception 'Invalid role';
  end if;
  -- Protect last admin
  if new_role = 'user' then
    select count(*) into admin_count from public.profiles where role = 'admin';
    if admin_count <= 1 then
      raise exception 'Cannot remove the last admin';
    end if;
  end if;
  if target_id = auth.uid() and new_role = 'user' then
    raise exception 'Cannot demote yourself';
  end if;
  update public.profiles set role = new_role where id = target_id;
end;
$$;

-- Delete a user account (admin only) — also deletes auth.users row
create or replace function public.admin_delete_user(target_id uuid)
returns void language plpgsql security definer as $$
declare
  admin_count int;
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'Unauthorized: admin role required';
  end if;
  if target_id = auth.uid() then
    raise exception 'Cannot delete your own account';
  end if;
  select count(*) into admin_count from public.profiles where role = 'admin';
  if (select role from public.profiles where id = target_id) = 'admin' and admin_count <= 1 then
    raise exception 'Cannot delete the last admin';
  end if;
  -- Delete from auth.users — cascades to profiles, bookmarks, folders
  delete from auth.users where id = target_id;
end;
$$;


-- ── 9. GRANT PERMISSIONS ──────────────────────────────────────────────
-- Allow authenticated users to call helper functions
grant execute on function public.admin_get_all_profiles()               to authenticated;
grant execute on function public.admin_set_user_status(uuid, text)      to authenticated;
grant execute on function public.admin_set_user_role(uuid, text)        to authenticated;
grant execute on function public.admin_delete_user(uuid)                to authenticated;

-- Allow anon/authenticated to read/write their own rows
grant select, insert, update, delete on public.profiles  to authenticated;
grant select, insert, update, delete on public.folders   to authenticated;
grant select, insert, update, delete on public.bookmarks to authenticated;


-- ── 10. REALTIME ──────────────────────────────────────────────────────
-- Enable Supabase Realtime for bookmarks and folders so changes sync
-- across browser tabs and devices instantly.
-- (Enable this in Supabase Dashboard → Database → Replication too)
alter publication supabase_realtime add table public.bookmarks;
alter publication supabase_realtime add table public.folders;


-- ══════════════════════════════════════════════════════════════════════
--  SETUP COMPLETE
--  Next steps:
--  1. Copy your Supabase Project URL and anon key from:
--     Supabase Dashboard → Project Settings → API
--  2. Paste them into the SUPABASE_URL and SUPABASE_ANON_KEY
--     constants at the top of bettermark.html
--  3. In Supabase Dashboard → Authentication → Settings:
--     • Disable "Confirm email" (or set up SMTP) for dev
--     • Set Site URL to: https://bettermark.netlify.app
--     • Add to Redirect URLs: https://bettermark.netlify.app/**
--  4. Deploy bettermark.html to Netlify — first user to sign up
--     automatically becomes admin.
-- ══════════════════════════════════════════════════════════════════════
