import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'content-type': 'application/json'
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: cors })

  const url = Deno.env.get('SUPABASE_URL')!
  const anon = Deno.env.get('SUPABASE_ANON_KEY')!
  const service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const authHeader = req.headers.get('Authorization') || ''
  const userClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } })
  const { data: userData } = await userClient.auth.getUser()
  const user = userData.user
  if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: cors })

  const { data: profile } = await userClient.from('profiles').select('role,active').eq('id', user.id).single()
  if (!profile?.active || !['owner','manager'].includes(profile.role)) {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: cors })
  }

  const body = await req.json()
  const action = body.action || 'create'
  const admin = createClient(url, service)

  if (action === 'create') {
    const role = String(body.role || '')
    if (!['manager','accountant','data_entry','viewer','client'].includes(role)) {
      return new Response(JSON.stringify({ error: 'Invalid role' }), { status: 400, headers: cors })
    }
    if (!body.email || !body.password) {
      return new Response(JSON.stringify({ error: 'Email and password are required' }), { status: 400, headers: cors })
    }
    if (role === 'client' && !body.client_id) {
      return new Response(JSON.stringify({ error: 'client_id is required for client role' }), { status: 400, headers: cors })
    }

    const { data, error } = await admin.auth.admin.createUser({
      email: body.email,
      password: body.password,
      email_confirm: true,
      user_metadata: { full_name: body.full_name || body.email }
    })
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: cors })

    await admin.from('profiles').update({
      full_name: body.full_name || body.email,
      email: body.email,
      role,
      active: true
    }).eq('id', data.user.id)

    if (role === 'client') {
      const { error: linkError } = await admin.from('client_portal_users').upsert({
        user_id: data.user.id,
        client_id: body.client_id,
        active: true
      })
      if (linkError) {
        await admin.auth.admin.deleteUser(data.user.id)
        return new Response(JSON.stringify({ error: linkError.message }), { status: 400, headers: cors })
      }
    }

    return new Response(JSON.stringify({ id: data.user.id, email: data.user.email }), { headers: cors })
  }

  if (action === 'delete') {
    if (!body.user_id || body.user_id === user.id) {
      return new Response(JSON.stringify({ error: 'Invalid user_id' }), { status: 400, headers: cors })
    }
    await admin.from('client_portal_users').delete().eq('user_id', body.user_id)
    const { error } = await admin.auth.admin.deleteUser(body.user_id)
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: cors })
    return new Response(JSON.stringify({ success: true }), { headers: cors })
  }

  return new Response(JSON.stringify({ error: 'Unsupported action' }), { status: 400, headers: cors })
})
