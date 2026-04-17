/* ============================================================
   ZENMARKET — Customer Orders API  (Vercel Serverless Function)
   ============================================================
   Endpoint: /api/orders
     POST → create a new order

   WHY THIS EXISTS:
     The browser Supabase client uses the anon/authenticated JWT.
     If the Supabase project's RLS policies were not yet applied
     (supabase-setup.sql never run), all direct INSERTs from the
     browser fail with a 42501 permission error and the order is
     silently saved only to localStorage — invisible to the admin.

     This endpoint uses the service-role key (set in Vercel env vars)
     which BYPASSES RLS entirely.  Orders posted here are always
     saved to the database regardless of policy configuration.

   SECURITY:
     - No secret token required (customer-facing).
     - The endpoint validates the shape of the payload and strips
       any fields the customer should not control (role, admin flags).
     - Rate limiting should be handled at the Vercel/CDN layer.
     - customer_id is accepted from the payload but never trusted
       for permissions — the endpoint simply records what was sent.
   ============================================================ */

const { createClient } = require('@supabase/supabase-js');

function getServiceClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set in environment.');
  return createClient(url, key, { auth: { persistSession: false } });
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.SITE_URL || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

const VALID_STATUSES         = ['pending','processing','confirmed','packed','shipped','delivered','cancelled','refunded'];
const VALID_PAYMENT_STATUSES = ['pending','paid','failed','refunded','cancelled'];
const VALID_PAYMENT_METHODS  = ['cod','bank','payhere','card','online'];

module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  let body;
  try {
    body = await readJson(req);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  // ── Basic validation ──────────────────────────────────────────
  if (!body.id || typeof body.id !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid order id' });
  }
  if (!body.total && body.total !== 0) {
    return res.status(400).json({ error: 'Missing order total' });
  }

  // ── Build a safe, sanitised row — never trust raw body directly ──
  const row = {
    id:             String(body.id).slice(0, 64),
    customer_id:    body.customer_id    ? String(body.customer_id).slice(0, 128) : null,
    customer_name:  body.customer_name  ? String(body.customer_name).slice(0, 256)  : '',
    customer_email: body.customer_email ? String(body.customer_email).slice(0, 256) : '',
    customer_phone: body.customer_phone ? String(body.customer_phone).slice(0, 64)  : '',
    items:          Array.isArray(body.items) ? body.items : [],
    subtotal:       Number(body.subtotal)  || 0,
    shipping:       Number(body.shipping)  || 0,
    discount:       Number(body.discount)  || 0,
    total:          Number(body.total)     || 0,
    status:         VALID_STATUSES.includes(body.status)
                      ? body.status : 'pending',
    payment_status: VALID_PAYMENT_STATUSES.includes(body.payment_status)
                      ? body.payment_status : 'pending',
    payment_method: VALID_PAYMENT_METHODS.includes(body.payment_method)
                      ? body.payment_method : 'cod',
    coupon_code:    body.coupon_code    ? String(body.coupon_code).slice(0, 64) : '',
    bank_ref:       body.bank_ref       ? String(body.bank_ref).slice(0, 256)   : null,
    payment_slip:   body.payment_slip   ? String(body.payment_slip).slice(0, 2048) : null,
    address:        body.address && typeof body.address === 'object' ? body.address : {},
    notes:          body.notes          ? String(body.notes).slice(0, 1024) : '',
    created_at:     body.created_at     || new Date().toISOString(),
    updated_at:     new Date().toISOString(),
  };

  try {
    const sb = getServiceClient();

    // INSERT — on duplicate ID (double-submit) UPDATE instead
    const { data, error } = await sb
      .from('orders')
      .insert(row)
      .select()
      .single();

    if (error) {
      // 23505 = unique_violation (duplicate order ID — double-submit / concurrent requests)
      if (error.code === '23505') {
        const { data: updated, error: updErr } = await sb
          .from('orders')
          .update({ ...row, updated_at: new Date().toISOString() })
          .eq('id', row.id)
          .select()
          .single();
        if (updErr) throw new Error(updErr.message);
        return res.status(200).json({ data: updated, deduplicated: true });
      }

      // 42P01 = table does not exist (supabase-setup.sql was never run)
      if (error.code === '42P01' || (error.message || '').includes('does not exist')) {
        console.error('[API /orders] orders table missing — run supabase-setup.sql');
        return res.status(503).json({
          error: 'Database not configured. Run supabase-setup.sql in Supabase → SQL Editor.',
          code:  'TABLE_MISSING',
          fix:   'https://supabase.com/dashboard → SQL Editor → paste supabase-setup.sql → Run',
        });
      }

      // 42501 = RLS permission denied (policies not applied from supabase-setup.sql)
      if (error.code === '42501' || (error.message || '').toLowerCase().includes('policy')) {
        console.error('[API /orders] RLS blocked INSERT — run supabase-setup.sql');
        return res.status(403).json({
          error: 'Row-level security is blocking the insert. Run supabase-setup.sql in Supabase → SQL Editor.',
          code:  'RLS_BLOCKED',
          fix:   'https://supabase.com/dashboard → SQL Editor → paste supabase-setup.sql → Run',
        });
      }

      throw new Error(error.message);
    }

    return res.status(201).json({ data });

  } catch (err) {
    // SUPABASE_SERVICE_ROLE_KEY or SUPABASE_URL not set in Vercel env vars
    if (err.message.includes('not set in environment')) {
      console.error('[API /orders] Missing env vars:', err.message);
      return res.status(503).json({
        error: err.message,
        code:  'ENV_MISSING',
        fix:   'Vercel → Project → Settings → Environment Variables → add SUPABASE_SERVICE_ROLE_KEY',
      });
    }
    console.error('[API /orders POST]', err.message);
    return res.status(500).json({ error: err.message });
  }
};
