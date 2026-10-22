import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || ''
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || ''

export function isConfigured() {
  return Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)
}

let db = null
let user = null
let listener = null
let chain = Promise.resolve()
let signingOut = false

function client() {
  if (!db) db = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
  return db
}

export function sessionUser() {
  return user
}

export async function currentAccessToken() {
  if (!isConfigured()) return null
  try {
    const { data } = await client().auth.getSession()
    return data.session?.access_token || null
  } catch {
    return null
  }
}

export async function rpc(fn, args) {
  if (!isConfigured()) throw new Error('Nuvem não configurada.')
  const { data, error } = await client().rpc(fn, args || {})
  if (error) throw new Error(error.message || 'Falha na consulta.')
  return data
}

export function setAuthListener(fn) {
  listener = fn
}

function emit() {
  if (listener) listener(user)
}

export async function init() {
  if (!isConfigured()) return null
  const { data } = await client().auth.getSession()
  user = data.session?.user || null
  client().auth.onAuthStateChange((_event, session) => {
    if (signingOut) {
      user = null
      return
    }
    const next = session?.user || null
    if (next?.id !== user?.id) {
      user = next
      emit()
    }
  })
  emit()
  return user
}

export async function signIn(email, password) {
  const { data, error } = await client().auth.signInWithPassword({ email, password })
  if (error) return { error: error.message }
  user = data.user
  emit()
  return { ok: true }
}

export async function signUp(email, password) {
  const { data, error } = await client().auth.signUp({ email, password })
  if (error) return { error: error.message }
  if (!data.session) return { ok: true, confirm: true }
  user = data.user
  emit()
  return { ok: true }
}

export async function signOut() {
  signingOut = true
  user = null
  emit()
  let error = null
  try {
    const res = await client().auth.signOut()
    error = res.error
  } catch (err) {
    error = err
  }
  user = null
  signingOut = false
  emit()
  return error ? { error: error.message || String(error) } : { ok: true }
}

function authUserId() {
  return user ? user.id : null
}

/* ============================== estado ============================== */

export function schedulePush(state) {
  if (!isConfigured() || !authUserId()) return Promise.resolve()
  const run = chain.then(() => pushState(state))
  chain = run.catch((err) => console.warn('push', err))
  return run
}

async function pushState(state) {
  const uid = authUserId()
  if (!uid) return
  const dbc = client()
  const settings = { ...(state.settings || {}) }
  delete settings.plan
  delete settings.planExpiresAt
  const { error: profErr } = await dbc
    .from('profiles')
    .upsert({ id: uid, settings, active_project_id: state.activeProjectId || null }, { onConflict: 'id' })
  if (profErr) throw profErr

  const { data: existing, error: selErr } = await dbc
    .from('projects')
    .select('id, is_shared')
    .eq('user_id', uid)
  if (selErr) throw selErr

  const serverShared = new Set((existing || []).filter((r) => r.is_shared).map((r) => r.id))
  const rows = (state.projects || [])
    .filter((p) => !p.shared && !serverShared.has(p.id))
    .map((p) => ({
      id: p.id,
      user_id: uid,
      name: p.name || 'Novo orçamento',
      client: p.client || '',
      phone: p.phone || '',
      notes: p.notes || '',
      billing_basis: p.billingBasis === 'rateio' ? 'rateio' : 'used',
      furniture: p.furniture || [],
      created_at: new Date(p.createdAt || Date.now()).toISOString()
    }))

  if (rows.length) {
    const { error: upErr } = await dbc.from('projects').upsert(rows, { onConflict: 'id' })
    if (upErr) throw upErr
  }

  const keep = new Set(rows.map((r) => r.id))
  const stale = (existing || [])
    .filter((r) => !r.is_shared && !keep.has(r.id))
    .map((r) => r.id)
  for (const id of stale) {
    const { error: delErr } = await dbc.from('projects').delete().eq('user_id', uid).eq('id', id)
    if (delErr) throw delErr
  }
}

export async function pullState() {
  const uid = authUserId()
  if (!uid) return null
  const dbc = client()

  const { data: prof, error: profErr } = await dbc
    .from('profiles')
    .select('settings, active_project_id, plan, plan_expires_at, mp_subscription_status')
    .eq('id', uid)
    .maybeSingle()
  if (profErr) throw profErr
  const { data: rows, error: rowsErr } = await dbc.rpc('list_my_projects')
  if (rowsErr) throw rowsErr

  const settings =
    prof && prof.settings && Object.keys(prof.settings).length ? { ...prof.settings } : {}
  if (prof) {
    settings.plan = prof.plan || settings.plan || 'gratis'
    settings.planExpiresAt = prof.plan_expires_at || ''
    settings.mpSubscriptionStatus = prof.mp_subscription_status || ''
  }

  if (!rows || rows.length === 0) {
    return { settings, activeProjectId: null, projects: [] }
  }

  const projects = rows.map((r) => ({
    id: r.id,
    name: r.name,
    client: r.client || '',
    phone: r.phone || '',
    notes: r.notes || '',
    billingBasis: r.billing_basis === 'rateio' ? 'rateio' : 'used',
    furniture: r.furniture || [],
    createdAt: new Date(r.created_at).getTime(),
    revision: Number(r.revision || 1),
    shared: !!r.is_shared || (r.role && r.role !== 'owner'),
    role: r.role || 'owner',
    sharedByName: r.shared_by_name || '',
    isOwner: !!r.is_owner,
    updatedAt: r.updated_at ? new Date(r.updated_at).getTime() : 0,
    updatedByName: r.updated_by_name || ''
  }))

  const activeProjectId =
    projects.some((p) => p.id === prof?.active_project_id) ? prof.active_project_id : projects[0].id

  return { settings, activeProjectId, projects }
}

/* ============================== compartilhamento ============================== */

export function listMyProjects() {
  return rpc('list_my_projects')
}

export function createProjectShare(projectId, opts = {}) {
  return rpc('create_project_share', {
    p_project_id: projectId,
    p_role: opts.role || 'editor',
    p_expires_hours: opts.expiresHours || 480,
    p_max_uses: opts.maxUses || 1
  })
}

export function acceptProjectShare(token) {
  return rpc('accept_project_share', { p_token: token })
}

export function saveSharedProject(projectId, expectedRevision, patch) {
  return rpc('save_shared_project', {
    p_project_id: projectId,
    p_expected_revision: expectedRevision,
    p_patch: patch
  })
}

export function leaveSharedProject(projectId) {
  return rpc('leave_shared_project', { p_project_id: projectId })
}

export function revokeProjectShare(projectId) {
  return rpc('revoke_project_share', { p_project_id: projectId })
}

export function removeProjectMember(projectId, userId) {
  return rpc('remove_project_member', {
    p_project_id: projectId,
    p_user_id: userId
  })
}

export function projectShareSummary(projectId) {
  return rpc('project_share_summary', { p_project_id: projectId })
}

export function subscribeProjectChanges(projectId, onChange) {
  if (!isConfigured() || !projectId || typeof onChange !== 'function') return () => {}
  const dbc = client()
  const channel = dbc
    .channel(`project-${projectId}-${Math.random().toString(36).slice(2)}`)
    .on(
      'postgres_changes',
      { event: 'UPDATE', schema: 'public', table: 'projects', filter: `id=eq.${projectId}` },
      (payload) => onChange(payload && payload.new)
    )
    .subscribe()
  return () => {
    try {
      dbc.removeChannel(channel)
    } catch {
      /* ignore */
    }
  }
}

export function subscribeMembershipChanges(userId, onChange) {
  if (!isConfigured() || !userId || typeof onChange !== 'function') return () => {}
  const dbc = client()
  const channel = dbc
    .channel(`members-${userId}-${Math.random().toString(36).slice(2)}`)
    .on(
      'postgres_changes',
      { event: '*', schema: 'public', table: 'project_members', filter: `user_id=eq.${userId}` },
      (payload) => onChange(payload)
    )
    .subscribe()
  return () => {
    try {
      dbc.removeChannel(channel)
    } catch {
      /* ignore */
    }
  }
}
