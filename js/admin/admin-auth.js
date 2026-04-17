/* ============================================================
   ZENMARKET — ADMIN AUTH
   ============================================================ */
import { LS, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_API_TOKEN } from '../config.js';
import { setAdminToken, clearAdminToken } from '../admin-api.js';
import {
  hashPassword, verifyPassword,
  checkBruteForce, recordFailedAttempt, clearFailedAttempts,
} from '../security-utils.js';

const PW_KEY = 'zm_admin_password_hash'; // localStorage cache key for password hash

// ── Get the current active password hash ─────────────────────
// Priority:
//   1. Supabase DB via /api/admin/config  (cross-device, production)
//   2. localStorage cache                 (offline fallback / demo mode)
//   3. Hash of ADMIN_PASSWORD from env.js (very first run)
async function getActivePasswordHash() {
  // In production, always try Supabase first so a password changed
  // on one device is immediately effective on all others.
  try {
    const res = await fetch('/api/admin/config?key=password_hash');
    if (res.ok) {
      const { value } = await res.json();
      if (value) {
        localStorage.setItem(PW_KEY, value); // keep a local cache
        return value;
      }
    }
  } catch {
    // Network unavailable — fall through to local cache
  }

  // Fall back to localStorage cache (demo mode or offline)
  try {
    const cached = localStorage.getItem(PW_KEY);
    if (cached) return cached;

    // Fallback: hash ADMIN_PASSWORD from env.js and cache it locally.
    // This runs on first login when the Supabase API hasn't stored a
    // password_hash yet, or when the API is unreachable.
    // Works in both DEMO_MODE and production as long as ADMIN_PASSWORD is set.
    if (!ADMIN_PASSWORD) return null;
    const h = await hashPassword(ADMIN_PASSWORD);
    localStorage.setItem(PW_KEY, h);
    return h;
  } catch {
    return null;
  }
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

export function requireAdmin() {
  const session = getAdminSession();
  if (!session) {
    const base = window.location.pathname.includes('/admin/') ? '' : 'admin/';
    window.location.href = base + 'index.html';
    return null;
  }
  // AUTH-03 fix: enforce session TTL — expire sessions older than 8 hours
  if (session.loginAt && (Date.now() - session.loginAt > SESSION_TTL_MS)) {
    adminLogout();
    return null;
  }
  return session;
}

export function getAdminSession() {
  try { return JSON.parse(localStorage.getItem(LS.adminSession) || 'null'); }
  catch { return null; }
}

export async function adminLogin(email, password) {
  // Brute-force guard
  const lockout = checkBruteForce();
  if (lockout) return { success: false, error: lockout };

  if (email !== ADMIN_EMAIL) {
    recordFailedAttempt();
    return { success: false, error: 'Invalid credentials' };
  }

  const activeHash = await getActivePasswordHash();
  const { match } = await verifyPassword(password, activeHash);

  if (!match) {
    recordFailedAttempt();
    return { success: false, error: 'Invalid credentials' };
  }

  clearFailedAttempts();
  const session = {
    email, role: 'admin', name: 'Admin User',
    loginAt: Date.now(),
  };
  localStorage.setItem(LS.adminSession, JSON.stringify(session));
  setAdminToken(ADMIN_API_TOKEN);  // allow AdminAPI calls (orders, reviews, etc.)
  return { success: true, session };
}

export function adminLogout() {
  localStorage.removeItem(LS.adminSession);
  clearAdminToken();
  const base = window.location.pathname.includes('/admin/') ? '' : 'admin/';
  window.location.href = base + 'index.html';
}

/**
 * Change the admin password.
 * @param {string} currentPw  - Must match the active password
 * @param {string} newPw      - New password (min 8 chars)
 * @returns {{ success: boolean, error?: string }}
 */
export async function changeAdminPassword(currentPw, newPw) {
  if (!currentPw || !newPw) return { success: false, error: 'All fields are required.' };

  // Validate the new password locally before making any API calls
  if (newPw.length < 8) return { success: false, error: 'New password must be at least 8 characters.' };
  if (newPw === currentPw) return { success: false, error: 'New password must be different from current.' };

  // Verify current password locally first (fast, no network round-trip)
  const activeHash = await getActivePasswordHash();
  const { match } = await verifyPassword(currentPw, activeHash);
  if (!match) return { success: false, error: 'Current password is incorrect.' };

  // Hash the new password (browser-side PBKDF2)
  const newHash = await hashPassword(newPw);

  // ── Persist to Supabase via API ───────────────────────────────
  // The server re-verifies currentPw independently using Node crypto,
  // so the hash is only updated if the caller truly knows the current password.
  try {
    const res = await fetch('/api/admin/config', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        key:             'password_hash',
        currentPassword: currentPw,   // raw password — server verifies it
        newValue:        newHash,
      }),
    });

    const json = await res.json().catch(() => ({}));

    if (!res.ok) {
      // If the API is unreachable (demo mode / local dev), fall back to
      // localStorage-only so the feature still works offline.
      if (res.status === 0 || res.status >= 500) {
        console.warn('[ZenMarket] Admin config API unreachable — saving to localStorage only.');
      } else {
        return { success: false, error: json.error || 'Failed to save password.' };
      }
    }
  } catch {
    // Network error or demo mode — continue with localStorage fallback
    console.warn('[ZenMarket] Admin config API unavailable — saving to localStorage only.');
  }

  // ── Always update local cache ──────────────────────────────────
  localStorage.setItem(PW_KEY, newHash);

  // Invalidate the current admin session — force re-login with new password
  localStorage.removeItem(LS.adminSession);
  clearAdminToken();

  return { success: true };
}

