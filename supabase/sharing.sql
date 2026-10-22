-- ============================================================================
-- MDF Atelier — compartilhamento vinculado de orçamentos
-- Aditivo: rode depois de schema.sql, billing.sql e admin.sql.
-- Não apaga dados existentes.
--
-- Modelo:
--   * projects continua sendo o documento canônico.
--   * project_members dá acesso ao mesmo project_id para outras contas.
--   * project_share_links guarda apenas o hash do token do link.
--   * project_revisions mantém histórico curto para conflito/recuperação.
-- ============================================================================

alter table public.projects
  add column if not exists revision bigint not null default 1,
  add column if not exists is_shared boolean not null default false,
  add column if not exists updated_by uuid;

create index if not exists projects_is_shared_idx
  on public.projects (is_shared)
  where is_shared = true;

create table if not exists public.project_members (
  project_id     text not null references public.projects (id) on delete cascade,
  user_id        uuid not null references auth.users (id) on delete cascade,
  role           text not null default 'editor'
                 check (role in ('owner', 'editor', 'viewer')),
  shared_by_name text not null default '',
  invited_by     uuid,
  joined_at      timestamptz not null default now(),
  primary key (project_id, user_id)
);

create index if not exists project_members_user_idx
  on public.project_members (user_id, joined_at desc);

create table if not exists public.project_share_links (
  id          uuid primary key default gen_random_uuid(),
  project_id  text not null references public.projects (id) on delete cascade,
  token_hash  text not null unique,
  role        text not null default 'editor'
              check (role in ('editor', 'viewer')),
  created_by  uuid not null references auth.users (id) on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  max_uses    integer not null default 1 check (max_uses > 0),
  uses        integer not null default 0 check (uses >= 0),
  revoked_at  timestamptz
);

create index if not exists project_share_links_project_idx
  on public.project_share_links (project_id, revoked_at, expires_at desc);

create table if not exists public.project_revisions (
  id         bigint generated always as identity primary key,
  project_id text not null references public.projects (id) on delete cascade,
  revision   bigint not null,
  data       jsonb not null,
  author_id  uuid,
  created_at timestamptz not null default now(),
  unique (project_id, revision)
);

create index if not exists project_revisions_project_idx
  on public.project_revisions (project_id, revision desc);

-- ----------------------------------------------------------------------------
-- Helpers de acesso (security definer para evitar recursão de RLS)
-- ----------------------------------------------------------------------------
create or replace function public.project_role_for_current(p_project_id text)
returns text language sql stable security definer set search_path = public as $$
  select case
    when auth.uid() is null then null
    when exists (
      select 1 from public.projects p
      where p.id = p_project_id and p.user_id = auth.uid()
    ) then 'owner'
    else (
      select m.role from public.project_members m
      where m.project_id = p_project_id and m.user_id = auth.uid()
      limit 1
    )
  end;
$$;

create or replace function public.can_access_project(p_project_id text)
returns boolean language sql stable security definer set search_path = public as $$
  select public.project_role_for_current(p_project_id) is not null;
$$;

create or replace function public.is_project_owner(p_project_id text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.projects p
    where p.id = p_project_id and p.user_id = auth.uid()
  );
$$;

create or replace function public.is_admin_safe(p_uid uuid)
returns boolean language plpgsql stable security definer set search_path = public as $$
declare
  v_exists boolean := false;
begin
  if p_uid is null then return false; end if;
  if to_regclass('public.admins') is null then return false; end if;
  execute 'select exists(select 1 from public.admins a where a.user_id = $1)'
    into v_exists using p_uid;
  return coalesce(v_exists, false);
end;
$$;

create or replace function public.refresh_project_shared(p_project_id text)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.projects p
     set is_shared = (
       exists (
         select 1 from public.project_members m
         where m.project_id = p_project_id
       )
       or exists (
         select 1 from public.project_share_links l
         where l.project_id = p_project_id
           and l.revoked_at is null
           and l.expires_at > now()
       )
     )
   where p.id = p_project_id;
end;
$$;

revoke all on function public.project_role_for_current(text) from public;
revoke all on function public.project_role_for_current(text) from anon;
grant execute on function public.project_role_for_current(text) to authenticated;

revoke all on function public.can_access_project(text) from public;
revoke all on function public.can_access_project(text) from anon;
grant execute on function public.can_access_project(text) to authenticated;

revoke all on function public.is_project_owner(text) from public;
revoke all on function public.is_project_owner(text) from anon;
grant execute on function public.is_project_owner(text) to authenticated;

revoke all on function public.is_admin_safe(uuid) from public;
revoke all on function public.is_admin_safe(uuid) from anon;
revoke all on function public.is_admin_safe(uuid) from authenticated;

revoke all on function public.refresh_project_shared(text) from public;
revoke all on function public.refresh_project_shared(text) from anon;
revoke all on function public.refresh_project_shared(text) from authenticated;

-- ----------------------------------------------------------------------------
-- RLS
-- ----------------------------------------------------------------------------
alter table public.project_members enable row level security;
alter table public.project_share_links enable row level security;
alter table public.project_revisions enable row level security;

drop policy if exists projects_select_member on public.projects;
create policy projects_select_member on public.projects
  for select using (public.can_access_project(id));

drop policy if exists project_members_select on public.project_members;
create policy project_members_select on public.project_members
  for select using (
    user_id = auth.uid() or public.is_project_owner(project_id)
  );

-- Sem policies de escrita: inserts/updates/deletes passam só pelas RPCs.

drop policy if exists project_revisions_select on public.project_revisions;
create policy project_revisions_select on public.project_revisions
  for select using (public.can_access_project(project_id));

-- ----------------------------------------------------------------------------
-- RPCs do compartilhamento
-- ----------------------------------------------------------------------------
create or replace function public.create_project_share(
  p_project_id text,
  p_role text default 'editor',
  p_expires_hours integer default 480,
  p_max_uses integer default 1
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_uid uuid := auth.uid();
  v_plan text;
  v_exp timestamptz;
  v_paid boolean;
  v_role text := case when p_role in ('editor', 'viewer') then p_role else 'editor' end;
  v_hours integer := greatest(1, coalesce(p_expires_hours, 480));
  v_max integer := greatest(1, coalesce(p_max_uses, 1));
  v_token text;
  v_hash text;
  v_link_id uuid;
  v_expires timestamptz;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (
    select 1 from public.projects p
    where p.id = p_project_id and p.user_id = v_uid
  ) then
    raise exception 'NOT_OWNER';
  end if;

  select plan, plan_expires_at into v_plan, v_exp
    from public.profiles where id = v_uid;
  v_paid := v_plan in ('pro', 'ultra', 'premium')
            and (v_exp is null or v_exp > now());
  if not v_paid and not public.is_admin_safe(v_uid) then
    raise exception 'SHARE_REQUIRES_PAID_PLAN';
  end if;

  v_token := encode(gen_random_bytes(32), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');
  v_expires := now() + make_interval(hours => v_hours);

  update public.project_share_links
     set revoked_at = now()
   where project_id = p_project_id
     and revoked_at is null;

  insert into public.project_share_links
    (project_id, token_hash, role, created_by, expires_at, max_uses)
  values
    (p_project_id, v_hash, v_role, v_uid, v_expires, v_max)
  returning id into v_link_id;

  update public.projects
     set is_shared = true, updated_by = v_uid
   where id = p_project_id;

  return jsonb_build_object(
    'ok', true,
    'token', v_token,
    'link_id', v_link_id,
    'expires_at', v_expires,
    'max_uses', v_max,
    'role', v_role
  );
end;
$$;

create or replace function public.accept_project_share(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_uid uuid := auth.uid();
  v_link public.project_share_links%rowtype;
  v_project public.projects%rowtype;
  v_owner_name text := '';
  v_existing text;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_token is null or length(p_token) < 16 then raise exception 'INVITE_INVALID'; end if;

  select * into v_link
    from public.project_share_links
   where token_hash = encode(digest(p_token, 'sha256'), 'hex')
     and revoked_at is null
     and expires_at > now()
     and uses < max_uses
   for update;

  if not found then raise exception 'INVITE_INVALID'; end if;

  select * into v_project from public.projects where id = v_link.project_id;
  if not found then raise exception 'INVITE_INVALID'; end if;

  if v_project.user_id = v_uid then
    return jsonb_build_object('ok', true, 'project_id', v_project.id, 'already', true);
  end if;

  select role into v_existing
    from public.project_members
   where project_id = v_link.project_id and user_id = v_uid;

  if v_existing is null then
    select coalesce(nullif(settings->>'shopName', ''), '') into v_owner_name
      from public.profiles where id = v_project.user_id;

    insert into public.project_members
      (project_id, user_id, role, shared_by_name, invited_by)
    values
      (v_link.project_id, v_uid, v_link.role, coalesce(v_owner_name, ''), v_link.created_by);

    update public.project_share_links set uses = uses + 1 where id = v_link.id;
  end if;

  return jsonb_build_object(
    'ok', true,
    'project_id', v_project.id,
    'name', v_project.name,
    'role', coalesce(v_existing, v_link.role),
    'shared_by_name', coalesce(v_owner_name, '')
  );
end;
$$;

create or replace function public.save_shared_project(
  p_project_id text,
  p_expected_revision bigint,
  p_patch jsonb
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_uid uuid := auth.uid();
  v_role text;
  v_row public.projects%rowtype;
  v_name text;
  v_client text;
  v_phone text;
  v_notes text;
  v_basis text;
  v_furniture jsonb;
  v_revision bigint;
  v_updated_at timestamptz;
  v_updater text := '';
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;

  v_role := public.project_role_for_current(p_project_id);
  if v_role is null then raise exception 'NO_ACCESS'; end if;
  if v_role not in ('owner', 'editor') then raise exception 'READ_ONLY'; end if;

  select * into v_row from public.projects where id = p_project_id for update;
  if not found then raise exception 'NOT_FOUND'; end if;

  select coalesce(nullif(pr.settings->>'shopName', ''), u.email, '')
    into v_updater
    from public.profiles pr
    left join auth.users u on u.id = pr.id
   where pr.id = v_row.updated_by;

  if p_expected_revision is distinct from v_row.revision then
    return jsonb_build_object(
      'ok', false,
      'code', 'conflict',
      'revision', v_row.revision,
      'updated_at', v_row.updated_at,
      'updated_by', v_row.updated_by,
      'updated_by_name', coalesce(v_updater, ''),
      'project', jsonb_build_object(
        'name', v_row.name,
        'client', v_row.client,
        'phone', v_row.phone,
        'notes', v_row.notes,
        'billingBasis', v_row.billing_basis,
        'furniture', v_row.furniture
      )
    );
  end if;

  v_name := coalesce(p_patch->>'name', v_row.name);
  v_client := coalesce(p_patch->>'client', v_row.client);
  v_phone := coalesce(p_patch->>'phone', v_row.phone);
  v_notes := coalesce(p_patch->>'notes', v_row.notes);
  v_basis := coalesce(p_patch->>'billingBasis', v_row.billing_basis);
  if v_basis not in ('used', 'rateio') then v_basis := 'used'; end if;
  v_furniture := case
    when p_patch ? 'furniture' then p_patch->'furniture'
    else v_row.furniture
  end;
  if jsonb_typeof(v_furniture) <> 'array' then v_furniture := v_row.furniture; end if;

  update public.projects
     set name = v_name,
         client = v_client,
         phone = v_phone,
         notes = v_notes,
         billing_basis = v_basis,
         furniture = v_furniture,
         revision = v_row.revision + 1,
         updated_by = v_uid
   where id = p_project_id
   returning revision, updated_at into v_revision, v_updated_at;

  insert into public.project_revisions (project_id, revision, data, author_id)
  values (
    p_project_id,
    v_revision,
    jsonb_build_object(
      'name', v_name,
      'client', v_client,
      'phone', v_phone,
      'notes', v_notes,
      'billingBasis', v_basis,
      'furniture', v_furniture
    ),
    v_uid
  )
  on conflict (project_id, revision) do nothing;

  delete from public.project_revisions
   where project_id = p_project_id
     and revision < v_revision - 100;

  select coalesce(nullif(pr.settings->>'shopName', ''), u.email, '')
    into v_updater
    from public.profiles pr
    left join auth.users u on u.id = pr.id
   where pr.id = v_uid;

  return jsonb_build_object(
    'ok', true,
    'revision', v_revision,
    'updated_at', v_updated_at,
    'updated_by', v_uid,
    'updated_by_name', v_updater
  );
end;
$$;

create or replace function public.leave_shared_project(p_project_id text)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if exists (
    select 1 from public.projects p
    where p.id = p_project_id and p.user_id = v_uid
  ) then
    raise exception 'OWNER_CANNOT_LEAVE';
  end if;

  delete from public.project_members
   where project_id = p_project_id and user_id = v_uid;

  perform public.refresh_project_shared(p_project_id);
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.revoke_project_share(p_project_id text)
returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_project_owner(p_project_id) then
    raise exception 'NOT_OWNER';
  end if;

  update public.project_share_links
     set revoked_at = now()
   where project_id = p_project_id
     and revoked_at is null;

  perform public.refresh_project_shared(p_project_id);
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.remove_project_member(p_project_id text, p_user_id uuid)
returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_project_owner(p_project_id) then
    raise exception 'NOT_OWNER';
  end if;
  if exists (
    select 1 from public.projects p
    where p.id = p_project_id and p.user_id = p_user_id
  ) then
    raise exception 'CANNOT_REMOVE_OWNER';
  end if;

  delete from public.project_members
   where project_id = p_project_id and user_id = p_user_id;

  perform public.refresh_project_shared(p_project_id);
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.project_share_summary(p_project_id text)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_link jsonb;
  v_members jsonb;
begin
  if not public.is_project_owner(p_project_id) then
    raise exception 'NOT_OWNER';
  end if;

  select jsonb_build_object(
           'id', l.id,
           'role', l.role,
           'expires_at', l.expires_at,
           'max_uses', l.max_uses,
           'uses', l.uses,
           'created_at', l.created_at
         )
    into v_link
    from public.project_share_links l
   where l.project_id = p_project_id
     and l.revoked_at is null
     and l.expires_at > now()
   order by l.created_at desc
   limit 1;

  select coalesce(jsonb_agg(
           jsonb_build_object(
             'user_id', m.user_id,
             'role', m.role,
             'name', coalesce(nullif(pr.settings->>'shopName', ''), u.email, ''),
             'email', coalesce(u.email, ''),
             'joined_at', m.joined_at
           )
           order by m.joined_at
         ), '[]'::jsonb)
    into v_members
    from public.project_members m
    left join public.profiles pr on pr.id = m.user_id
    left join auth.users u on u.id = m.user_id
   where m.project_id = p_project_id;

  return jsonb_build_object(
    'ok', true,
    'active_link', v_link,
    'members', v_members
  );
end;
$$;

create or replace function public.list_my_projects()
returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', t.id,
        'name', t.name,
        'client', t.client,
        'phone', t.phone,
        'notes', t.notes,
        'billing_basis', t.billing_basis,
        'furniture', t.furniture,
        'created_at', t.created_at,
        'updated_at', t.updated_at,
        'revision', t.revision,
        'is_shared', t.is_shared,
        'updated_by', t.updated_by,
        'updated_by_name', t.updated_by_name,
        'role', t.role,
        'shared_by_name', t.shared_by_name,
        'is_owner', t.is_owner
      )
      order by t.updated_at desc, t.created_at desc
    ),
    '[]'::jsonb
  )
  from (
    select p.*,
           case when p.user_id = auth.uid() then 'owner' else m.role end as role,
           case when p.user_id = auth.uid() then '' else coalesce(m.shared_by_name, '') end as shared_by_name,
           (p.user_id = auth.uid()) as is_owner,
           coalesce(nullif(up.settings->>'shopName', ''), uu.email, '') as updated_by_name
      from public.projects p
      left join public.project_members m
        on m.project_id = p.id and m.user_id = auth.uid()
      left join public.profiles up on up.id = p.updated_by
      left join auth.users uu on uu.id = p.updated_by
     where p.user_id = auth.uid() or m.user_id = auth.uid()
  ) t;
$$;

revoke all on function public.create_project_share(text, text, integer, integer) from public;
revoke all on function public.create_project_share(text, text, integer, integer) from anon;
grant execute on function public.create_project_share(text, text, integer, integer) to authenticated;

revoke all on function public.accept_project_share(text) from public;
revoke all on function public.accept_project_share(text) from anon;
grant execute on function public.accept_project_share(text) to authenticated;

revoke all on function public.save_shared_project(text, bigint, jsonb) from public;
revoke all on function public.save_shared_project(text, bigint, jsonb) from anon;
grant execute on function public.save_shared_project(text, bigint, jsonb) to authenticated;

revoke all on function public.leave_shared_project(text) from public;
revoke all on function public.leave_shared_project(text) from anon;
grant execute on function public.leave_shared_project(text) to authenticated;

revoke all on function public.revoke_project_share(text) from public;
revoke all on function public.revoke_project_share(text) from anon;
grant execute on function public.revoke_project_share(text) to authenticated;

revoke all on function public.remove_project_member(text, uuid) from public;
revoke all on function public.remove_project_member(text, uuid) from anon;
grant execute on function public.remove_project_member(text, uuid) to authenticated;

revoke all on function public.project_share_summary(text) from public;
revoke all on function public.project_share_summary(text) from anon;
grant execute on function public.project_share_summary(text) to authenticated;

revoke all on function public.list_my_projects() from public;
revoke all on function public.list_my_projects() from anon;
grant execute on function public.list_my_projects() to authenticated;

-- ----------------------------------------------------------------------------
-- Realtime (ignora se a publicação não existir no projeto)
-- ----------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = 'projects'
    ) then
      alter publication supabase_realtime add table public.projects;
    end if;

    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = 'project_members'
    ) then
      alter publication supabase_realtime add table public.project_members;
    end if;
  end if;
end $$;
