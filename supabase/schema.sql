-- Kitchen Stock Control v0.6
-- Run once in Supabase SQL Editor. Safe foundation: no data is imported or deleted here.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'editor' check (role in ('admin','editor')),
  created_at timestamptz not null default now()
);

create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.can_edit_inventory()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_user_role() in ('admin','editor'), false)
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, display_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name',''), 'editor')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create table if not exists public.categories (
  name text primary key,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id text primary key,
  name text not null,
  category text not null references public.categories(name) on update cascade,
  control_type text not null check (control_type in ('percent','quantity')),
  unit text not null default '',
  min_value numeric not null default 0,
  initial_value numeric,
  pack_qty numeric,
  pack_unit text,
  note text not null default '',
  aliases text not null default '',
  is_active boolean not null default true,
  created_by uuid references auth.users(id),
  updated_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.inventory_snapshots (
  id uuid primary key default gen_random_uuid(),
  stock_date date not null,
  saved_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);

create table if not exists public.inventory_values (
  snapshot_id uuid not null references public.inventory_snapshots(id) on delete cascade,
  product_id text not null references public.products(id) on update cascade,
  value numeric,
  primary key (snapshot_id, product_id)
);

create table if not exists public.stock_checks (
  stock_date date not null,
  product_id text not null references public.products(id) on update cascade on delete cascade,
  checked_at timestamptz not null default now(),
  checked_by uuid references auth.users(id),
  primary key (stock_date, product_id)
);

create table if not exists public.recipes (
  id text primary key,
  name text not null,
  output_product_id text references public.products(id) on update cascade on delete set null,
  yield_qty numeric,
  yield_unit text,
  steps text not null default '',
  notes text not null default '',
  created_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);

create table if not exists public.recipe_items (
  id uuid primary key default gen_random_uuid(),
  recipe_id text not null references public.recipes(id) on delete cascade,
  product_id text references public.products(id) on update cascade on delete set null,
  ingredient_name text not null default '',
  quantity numeric not null default 0,
  unit text not null default 'g',
  note text not null default ''
);

create table if not exists public.app_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id text primary key,
  type text not null,
  title text not null,
  body text not null default '',
  product_id text references public.products(id) on update cascade on delete set null,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id),
  is_read boolean not null default false
);

create table if not exists public.activity_log (
  id uuid primary key default gen_random_uuid(),
  action text not null,
  entity_type text not null,
  entity_id text,
  description text not null default '',
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create index if not exists idx_snapshots_date on public.inventory_snapshots(stock_date desc, saved_at desc);
create index if not exists idx_values_product on public.inventory_values(product_id);
create index if not exists idx_activity_created on public.activity_log(created_at desc);
create index if not exists idx_notifications_created on public.notifications(created_at desc);

-- Enable RLS on every application table.
alter table public.profiles enable row level security;
alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.inventory_snapshots enable row level security;
alter table public.inventory_values enable row level security;
alter table public.stock_checks enable row level security;
alter table public.recipes enable row level security;
alter table public.recipe_items enable row level security;
alter table public.app_settings enable row level security;
alter table public.notifications enable row level security;
alter table public.activity_log enable row level security;

-- Profiles: users can see their own profile; admins can see all.
drop policy if exists "profiles_read_self_or_admin" on public.profiles;
create policy "profiles_read_self_or_admin" on public.profiles
for select to authenticated
using (id = auth.uid() or public.current_user_role() = 'admin');

-- The app may edit only display_name. Role changes are reserved for the SQL/admin workflow.
grant select on public.profiles to authenticated;
grant update (display_name) on public.profiles to authenticated;

-- Authenticated kitchen users can view and manage inventory data.
do $$
declare t text;
begin
  foreach t in array array['categories','products','inventory_snapshots','inventory_values','stock_checks','recipes','recipe_items','app_settings','notifications','activity_log']
  loop
    execute format('drop policy if exists "authenticated_read_%s" on public.%I', t, t);
    execute format('create policy "authenticated_read_%s" on public.%I for select to authenticated using (true)', t, t);
    execute format('drop policy if exists "inventory_edit_%s" on public.%I', t, t);
    execute format('create policy "inventory_edit_%s" on public.%I for all to authenticated using (public.can_edit_inventory()) with check (public.can_edit_inventory())', t, t);
  end loop;
end $$;

grant select, insert, update, delete on
  public.categories, public.products, public.inventory_snapshots,
  public.inventory_values, public.stock_checks, public.recipes,
  public.recipe_items, public.app_settings, public.notifications,
  public.activity_log to authenticated;

-- Enable Supabase Realtime for shared live updates.
do $$
begin
  alter publication supabase_realtime add table public.products;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.categories;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.inventory_snapshots;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.inventory_values;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.stock_checks;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.notifications;
exception when duplicate_object then null;
end $$;

-- IMPORTANT: new sign-ups start as editor. After creating your own account,
-- promote only your account to admin from the SQL Editor using your exact email:
-- update public.profiles p set role = 'admin'
-- from auth.users u where p.id = u.id and u.email = 'YOUR_LOGIN_EMAIL';
