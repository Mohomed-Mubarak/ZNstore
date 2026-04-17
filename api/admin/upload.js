/* ============================================================
   ZENMARKET — Admin Image Upload API  (Vercel Serverless)
   ============================================================
   Endpoint: POST /api/admin/upload
   Accepts:  multipart/form-data  { file, productId }
             OR application/json  { base64, filename, contentType, productId }

   Why server-side?
     The browser admin session is NOT a Supabase native auth session
     (it uses custom localStorage auth). Direct client-side uploads
     are blocked by Supabase RLS because the browser has no Supabase JWT.
     This endpoint uses the SERVICE ROLE KEY which bypasses RLS entirely.

   Security:
     - Requires X-Admin-Token header (same as all /api/admin/* routes)
     - File validated: type + size enforced server-side
     - Path scoped to  products/{productId}/  to prevent path traversal
   ============================================================ */

const { createClient } = require('@supabase/supabase-js');

// ── Vercel runtime config ─────────────────────────────────────────
// CRITICAL: disable Vercel's automatic body parser so readBody() can
// read the raw stream. Without this, Vercel consumes the stream before
// the handler runs, readBody() returns an empty buffer, and large
// base64 payloads also exceed Vercel's default 1 MB JSON parse limit
// — causing the request to fail with HTTP 405 before reaching any
// handler logic.
//
// NOTE: config MUST be attached to the handler function AFTER it is
// defined (see bottom of file). Setting module.exports.config here
// then reassigning module.exports = handler below destroys the config.
// The correct pattern is:  handler.config = {...}; module.exports = handler;

const BUCKET          = 'product-images';
const MAX_SIZE_BYTES  = 5 * 1024 * 1024;   // 5 MB
const ALLOWED_TYPES   = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif'];

// ── Supabase admin client (service role — bypasses RLS) ──────────
function getAdminClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars');
  return createClient(url, key, { auth: { persistSession: false } });
}

// ── Auth check ───────────────────────────────────────────────────
function isAuthorised(req) {
  const token    = req.headers['x-admin-token'];
  const expected = process.env.ADMIN_API_TOKEN;
  if (!expected || !token) return false;
  if (token.length !== expected.length) return false;
  return require('crypto').timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

// ── CORS ─────────────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin',  process.env.SITE_URL || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
}

// ── Read raw body as Buffer ───────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  ()  => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Safe filename ─────────────────────────────────────────────────
function safeName(original) {
  const ext   = (original.match(/\.([a-z0-9]+)$/i) || [])[1] || 'jpg';
  const base  = original
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-z0-9]/gi, '-')
    .toLowerCase()
    .slice(0, 40);
  return `${Date.now()}-${base}.${ext}`;
}

// ── Parse multipart/form-data (minimal, no deps) ─────────────────
function parseMultipart(buffer, boundary) {
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const parts       = [];
  let   start       = 0;

  while (start < buffer.length) {
    const bStart = buffer.indexOf(boundaryBuf, start);
    if (bStart === -1) break;

    const headerStart = bStart + boundaryBuf.length + 2;  // skip \r\n
    const headerEnd   = buffer.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;

    const headers   = buffer.slice(headerStart, headerEnd).toString();
    const dataStart = headerEnd + 4;
    const nextBound = buffer.indexOf(boundaryBuf, dataStart);
    const dataEnd   = nextBound === -1 ? buffer.length : nextBound - 2;  // strip \r\n before next boundary

    const data = buffer.slice(dataStart, dataEnd);

    const nameMatch     = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    const ctMatch       = headers.match(/Content-Type:\s*([^\r\n]+)/i);

    parts.push({
      name:        nameMatch     ? nameMatch[1]     : null,
      filename:    filenameMatch ? filenameMatch[1] : null,
      contentType: ctMatch       ? ctMatch[1].trim(): 'application/octet-stream',
      data,
    });

    start = nextBound === -1 ? buffer.length : nextBound;
  }

  return parts;
}

// ── Main handler ─────────────────────────────────────────────────
async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });
  if (!isAuthorised(req))       return res.status(401).json({ error: 'Unauthorised' });

  try {
    const supabase    = getAdminClient();
    const rawBody     = await readBody(req);
    const contentType = req.headers['content-type'] || '';

    let fileBuffer, filename, mimeType, productId;

    // ── Branch A: JSON base64 payload ────────────────────────────
    if (contentType.includes('application/json')) {
      const payload = JSON.parse(rawBody.toString());
      if (!payload.base64 || !payload.filename || !payload.contentType) {
        return res.status(400).json({ error: 'base64, filename and contentType are required' });
      }
      fileBuffer  = Buffer.from(payload.base64, 'base64');
      filename    = payload.filename;
      mimeType    = payload.contentType;
      productId   = payload.productId || 'new';

    // ── Branch B: multipart/form-data ─────────────────────────────
    } else if (contentType.includes('multipart/form-data')) {
      const boundaryMatch = contentType.match(/boundary=([^\s;]+)/);
      if (!boundaryMatch) return res.status(400).json({ error: 'Missing multipart boundary' });

      const parts = parseMultipart(rawBody, boundaryMatch[1]);
      const filePart = parts.find(p => p.filename) || parts.find(p => p.name === 'file');
      const idPart   = parts.find(p => p.name === 'productId');

      if (!filePart) return res.status(400).json({ error: 'No file found in request' });

      fileBuffer  = filePart.data;
      filename    = filePart.filename;
      mimeType    = filePart.contentType;
      productId   = idPart ? idPart.data.toString().trim() : 'new';

    } else {
      return res.status(415).json({ error: 'Unsupported Content-Type. Use application/json or multipart/form-data' });
    }

    // ── Validate ──────────────────────────────────────────────────
    if (!ALLOWED_TYPES.includes(mimeType)) {
      return res.status(400).json({ error: `Unsupported file type: ${mimeType}` });
    }
    if (fileBuffer.length > MAX_SIZE_BYTES) {
      return res.status(400).json({ error: `File exceeds 5 MB limit (${(fileBuffer.length / 1024 / 1024).toFixed(1)} MB)` });
    }

    // ── Upload via service role (bypasses RLS) ────────────────────
    const folder = productId === 'blog' ? 'blog' : `products/${productId}`;
    const path = `${folder}/${safeName(filename)}`;

    const { data, error } = await supabase.storage
      .from(BUCKET)
      .upload(path, fileBuffer, {
        contentType:  mimeType,
        cacheControl: '31536000',
        upsert:       false,
      });

    if (error) throw new Error(error.message);

    const { data: urlData } = supabase.storage.from(BUCKET).getPublicUrl(data.path);

    return res.status(200).json({ url: urlData.publicUrl, path: data.path });

  } catch (err) {
    console.error('[Upload API]', err.message);
    return res.status(500).json({ error: err.message });
  }
}

// MUST be set on the function AFTER it is defined.
// Setting module.exports.config before module.exports = handler
// overwrites the config — Vercel never sees bodyParser:false and
// the 1 MB default limit causes HTTP 405 on base64 image uploads.
handler.config = {
  api: {
    bodyParser: false,    // let readBody() handle the raw stream
    responseLimit: false, // no artificial cap on response size
  },
};

module.exports = handler;
