/* ============================================================
   ZENMARKET — Admin Users API  (Vercel Serverless Function)
   ============================================================
   Endpoint: /api/admin/users
     DELETE ?id=<uuid>  → hard-delete user from auth.users
                          (profiles row is removed automatically
                           via ON DELETE CASCADE)

   Why a serverless function?
     auth.admin.deleteUser() requires the SERVICE ROLE KEY which
     must NEVER be sent to the browser. The browser-side admin
     pages call this endpoint with the X-Admin-Token header;
     the actual Supabase auth deletion happens server-side only.
   ============================================================ */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

function getAdminClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('Missing Supabase env vars');
  return createClient(url, key, { auth: { persistSession: false } });
}

function isAuthorised(req) {
  const token    = req.headers['x-admin-token'];
  const expected = process.env.ADMIN_API_TOKEN;
  if (!expected || !token) return false;
  if (token.length !== expected.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(token),
    Buffer.from(expected)
  );
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin',  process.env.SITE_URL || '*');
  res.setHeader('Access-Control-Allow-Methods', 'DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
}

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (!isAuthorised(req)) {
    return res.status(401).json({ error: 'Unauthorised' });
  }

  if (req.method !== 'DELETE') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ error: 'Missing user id' });
  }

  try {
    const supabase = getAdminClient();

    // auth.admin.deleteUser removes the row from auth.users.
    // The profiles table has ON DELETE CASCADE, so the profile
    // row is automatically removed — no second query needed.
    const { error } = await supabase.auth.admin.deleteUser(id);

    if (error) {
      console.error('[Admin Users] auth.admin.deleteUser failed:', error.message);
      return res.status(500).json({ error: error.message });
    }

    console.log(`[Admin Users] Deleted auth user ${id}`);
    return res.status(200).json({ deleted: true, id });

  } catch (err) {
    console.error('[Admin Users] Unexpected error:', err.message);
    return res.status(500).json({ error: err.message });
  }
};
