/* ============================================================
   ZENMARKET — SUPABASE CLIENT  (v29 — Full Stack)
   ============================================================
   Single source of truth for the Supabase client instance.
   Returns null in DEMO_MODE so every caller can gracefully
   fall back to localStorage without crashing.

   SETUP:
     1. Create project at https://supabase.com
     2. Project Settings → API → copy URL + anon key
     3. Set in .env then run: node build.js
        Or add to Vercel → Settings → Environment Variables
     4. Set DEMO_MODE=false in .env
   ============================================================ */
import { SUPABASE_URL, SUPABASE_ANON_KEY, DEMO_MODE } from './config.js';

let _client = null;

/**
 * Returns the Supabase client singleton.
 * Returns null in DEMO_MODE so callers fall back to localStorage.
 */
export function getSupabase() {
  if (DEMO_MODE) return null;
  if (_client) return _client;

  if (!window.supabase) {
    console.error('[ZenMarket] Supabase CDN not loaded. Check your HTML <script> tag.');
    return null;
  }

  if (!SUPABASE_URL || SUPABASE_URL.includes('YOUR_PROJECT')) {
    console.error('[ZenMarket] SUPABASE_URL is not configured. Run node build.js after filling .env');
    return null;
  }

  _client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession:     true,
      autoRefreshToken:   true,
      detectSessionInUrl: true,
    },
    realtime: {
      params: {
        eventsPerSecond: 10,
      },
    },
    global: {
      headers: {
        'x-application-name': 'zenmarket-storefront',
      },
    },
  });

  return _client;
}

/**
 * Destroy the client singleton.
 * Call before creating a new client (e.g. after config change in tests).
 */
export function resetSupabaseClient() {
  _client = null;
}

// ── Typed query helpers ───────────────────────────────────────────

/**
 * Execute a Supabase query and throw on error.
 * @template T
 * @param {Promise<{data: T, error: object}>} query
 * @returns {Promise<T>}
 */
export async function query(supabaseQuery) {
  // Race against a 6-second timeout so a slow/offline Supabase never hangs the page
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Supabase query timeout')), 6000)
  );
  const { data, error } = await Promise.race([supabaseQuery, timeout]);
  if (error) throw new Error(error.message);
  return data ?? [];
}

/**
 * Execute a Supabase query and return null on error (silent).
 * Use for non-critical reads where a missing value is acceptable.
 * @template T
 * @param {Promise<{data: T, error: object}>} supabaseQuery
 * @returns {Promise<T|null>}
 */
export async function querySafe(supabaseQuery) {
  try {
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Supabase query timeout')), 6000)
    );
    const { data, error } = await Promise.race([supabaseQuery, timeout]);
    if (error) { console.warn('[Supabase]', error.message); return null; }
    return data;
  } catch(e) { console.warn('[Supabase querySafe]', e.message); return null; }
}
