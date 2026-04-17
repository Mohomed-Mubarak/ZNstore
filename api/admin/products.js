/* ============================================================
   ZENMARKET — Admin Products API  (Vercel Serverless Function)
   ============================================================
   Endpoint: /api/admin/products
     GET    → list all products (including inactive)
     POST   → create product
     PUT    → update product  (?id=xxx)
     DELETE → delete product  (?id=xxx)

   SECURITY:
     - Requires X-Admin-Token header matching ADMIN_API_TOKEN env var
     - Uses Supabase service role key — bypasses RLS for admin ops
     - Rate-limited by Vercel Edge Network + Cloudflare
   ============================================================ */

const { createClient } = require('@supabase/supabase-js');

function getAdminClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('Missing Supabase env vars');
  return createClient(url, key, { auth: { persistSession: false } });
}

// ── Auth middleware ──────────────────────────────────────────────
function isAuthorised(req) {
  const token = req.headers['x-admin-token'];
  const expected = process.env.ADMIN_API_TOKEN;
  if (!expected || !token) return false;
  // Constant-time comparison to prevent timing attacks
  return token.length === expected.length &&
    require('crypto').timingSafeEqual(
      Buffer.from(token),
      Buffer.from(expected)
    );
}

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── CORS headers ─────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.SITE_URL || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
}

module.exports = async function handler(req, res) {
  cors(res);

  if (req.method === 'OPTIONS') return res.status(204).end();

  if (!isAuthorised(req)) {
    return res.status(401).json({ error: 'Unauthorised' });
  }

  const supabase = getAdminClient();
  const { id }   = req.query;

  try {
    // ── GET — list all products ──────────────────────────────────
    if (req.method === 'GET') {
      const { page = '1', limit = '50', search = '', category = '' } = req.query;
      const from = (parseInt(page) - 1) * parseInt(limit);
      const to   = from + parseInt(limit) - 1;

      let query = supabase
        .from('products')
        .select('*', { count: 'exact' })
        .order('created_at', { ascending: false })
        .range(from, to);

      if (search) query = query.ilike('name', `%${search}%`);
      if (category) query = query.eq('category_slug', category);

      const { data, error, count } = await query;
      if (error) throw error;

      return res.status(200).json({ data, count, page: parseInt(page), limit: parseInt(limit) });
    }

    // ── POST — create product ────────────────────────────────────
    if (req.method === 'POST') {
      const body = await readJson(req);

      // Validate required fields
      if (!body.name || !body.price) {
        return res.status(400).json({ error: 'name and price are required' });
      }

      // Generate slug if not provided
      if (!body.slug) {
        body.slug = body.name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-|-$/g, '');
      }

      body.id         = body.id || `prod-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      body.created_at = new Date().toISOString();
      body.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('products')
        .insert(body)
        .select()
        .single();

      if (error) throw error;
      return res.status(201).json({ data });
    }

    // ── PUT — update product ─────────────────────────────────────
    if (req.method === 'PUT') {
      if (!id) return res.status(400).json({ error: 'Missing product id' });
      const body = await readJson(req);
      body.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('products')
        .update(body)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;
      return res.status(200).json({ data });
    }

    // ── DELETE — soft delete (set active=false) ──────────────────
    if (req.method === 'DELETE') {
      if (!id) return res.status(400).json({ error: 'Missing product id' });

      const { error } = await supabase
        .from('products')
        .update({ active: false, updated_at: new Date().toISOString() })
        .eq('id', id);

      if (error) throw error;
      return res.status(200).json({ deleted: id });
    }

    return res.status(405).json({ error: 'Method not allowed' });

  } catch (err) {
    console.error('[Admin Products API]', err.message);
    return res.status(500).json({ error: err.message });
  }
};
