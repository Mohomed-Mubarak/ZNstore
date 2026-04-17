/* ============================================================
   ZENMARKET — STORE ADAPTER  (v29 — Full Stack)
   ============================================================
   Unified data access layer that routes to the correct backend:

   DEMO_MODE=true  → js/store.js      (localStorage, works offline)
   DEMO_MODE=false → js/supabase-store.js (PostgreSQL via Supabase)

   USAGE (replace direct store.js imports with this module):

     // Before:
     import { getProducts, saveOrder } from './store.js';

     // After:
     import { getProducts, saveOrder } from './store-adapter.js';

   The adapter exports the same function names as both backends,
   so switching is a one-line import change per file.

   ASYNC NOTE:
     In DEMO_MODE, store.js functions are synchronous.
     In production, supabase-store.js functions are async.
     The adapter wraps demo functions in Promise.resolve() so
     callers can always use await safely.
   ============================================================ */

import { DEMO_MODE } from './config.js';

// ── Dynamic import based on mode ─────────────────────────────────

let _store = null;

async function getStore() {
  if (_store) return _store;
  if (DEMO_MODE) {
    _store = await import('./store.js');
  } else {
    _store = await import('./supabase-store.js');
  }
  return _store;
}

// ── Helper to wrap sync demo functions as async ───────────────────

function wrap(fn) {
  return async (...args) => {
    const store = await getStore();
    // In production (DEMO_MODE=false) errors from supabase-store.js are always
    // re-thrown so they surface to the caller. There is no silent localStorage
    // fallback — orders must reach Supabase or the caller must handle the error.
    const result = store[fn]?.(...args);
    return result instanceof Promise ? await result : result;
  };
}

// ── Products ──────────────────────────────────────────────────────

export const getProducts      = wrap('getProducts');
export const getProduct       = wrap('getProduct');
export const searchProducts   = wrap('searchProducts');
export const decrementStock   = wrap('decrementStock');

// Admin mutations — save/delete persist to Supabase in production,
// localStorage in demo mode.
export const saveProduct   = wrap('saveProduct');
export const deleteProduct = wrap('deleteProduct');

// Pure utility helpers — same implementation in both backends.
export async function generateProductId() {
  const store = await getStore();
  return store.generateProductId();
}
export async function generateSlug(name) {
  const store = await getStore();
  return store.generateSlug(name);
}

// ── Orders ────────────────────────────────────────────────────────

export const saveOrder    = wrap('saveOrder');
export const getMyOrders  = wrap('getMyOrders');
export const getOrder     = wrap('getOrder');

// ── Categories ────────────────────────────────────────────────────

export const getCategories  = wrap('getCategories');
export const saveCategories = wrap('saveCategories');

// ── Coupons ───────────────────────────────────────────────────────

export const getCoupon             = wrap('getCoupon');
export const incrementCouponUsage  = wrap('incrementCouponUsage');

// ── Shipping ──────────────────────────────────────────────────────

export const getShippingZones = wrap('getShippingZones');

// ── Reviews ───────────────────────────────────────────────────────

export const getProductReviews = wrap('getProductReviews');
export const submitReview      = wrap('submitReview');

// ── Profile ───────────────────────────────────────────────────────

export const getProfile    = wrap('getProfile');
export const updateProfile = wrap('updateProfile');

// ── Contact ───────────────────────────────────────────────────────

export const saveContactMessage = wrap('saveContactMessage');

// ── Orders (admin full CRUD) ──────────────────────────────────────

export const getOrders    = wrap('getOrders');
export const saveOneOrder = wrap('saveOneOrder');
export const updateOrder  = wrap('updateOrder');
export const deleteOrder  = wrap('deleteOrder');
export const deleteOrders = wrap('deleteOrders');

// ── Coupons (admin full CRUD) ─────────────────────────────────────

export const getCoupons  = wrap('getCoupons');
export const saveCoupons = wrap('saveCoupons');
export const insertCoupon = wrap('insertCoupon');
export const deleteCoupon = wrap('deleteCoupon');
export const toggleCoupon = wrap('toggleCoupon');

// ── Shipping zones (admin save) ───────────────────────────────────

export const saveShippingZones = wrap('saveShippingZones');

// ── Users (admin) ─────────────────────────────────────────────────

export const getUsers  = wrap('getUsers');
export const saveUsers = wrap('saveUsers');

// ── Blog posts ────────────────────────────────────────────────────

export const getBlogPosts   = wrap('getBlogPosts');
export const getBlogPost    = wrap('getBlogPost');
export const saveBlogPost   = wrap('saveBlogPost');
export const savePosts      = wrap('savePosts');
export const getPosts       = wrap('getPosts');
export const deleteBlogPost = wrap('deleteBlogPost');

// ── Notifications ─────────────────────────────────────────────────

export const getNotifications         = wrap('getNotifications');
export const addNotification          = wrap('addNotification');
export const markNotificationRead     = wrap('markNotificationRead');
export const markAllNotificationsRead = wrap('markAllNotificationsRead');

// ── Site settings ─────────────────────────────────────────────────

export const getSiteSettings  = wrap('getSiteSettings');
export const saveSiteSettings = wrap('saveSiteSettings');

// ── Mode info ─────────────────────────────────────────────────────

export const IS_DEMO = DEMO_MODE;

export function getDataMode() {
  return DEMO_MODE ? 'localStorage (demo)' : 'Supabase (production)';
}

// ── Reviews (extended admin + user) ───────────────────────────

export const getProductReviewsAdmin  = wrap('getProductReviewsAdmin');
export const getAllReviewsFlat        = wrap('getAllReviewsFlat');
export const getUserReview            = wrap('getUserReview');
export const getUserReviews           = wrap('getUserReviews');
export const editReview               = wrap('editReview');
export const approveReview            = wrap('approveReview');
export const rejectReview             = wrap('rejectReview');
export const submitReviewV2           = wrap('submitReviewV2');

// ── Addresses ─────────────────────────────────────────────────

export const getAddressesSupabase  = wrap('getAddresses');
export const saveAddressesSupabase = wrap('saveAddresses');

// ── Newsletter ─────────────────────────────────────────────────

export const saveNewsletterSubscriber   = wrap('saveNewsletterSubscriber');
export const getNewsletterSubscribers   = wrap('getNewsletterSubscribers');
export const deleteNewsletterSubscriber = wrap('deleteNewsletterSubscriber');

// ── Contact Messages (full CRUD) ───────────────────────────────

export const getContactMessages      = wrap('getContactMessages');
export const markContactMessageRead  = wrap('markContactMessageRead');
export const deleteContactMessage    = wrap('deleteContactMessage');

// ── Shipping helpers (utility functions from store.js / supabase-store.js) ───
// getShippingRate and getDeliveryDays are utility helpers defined in store.js.
// In production we read from the zones in Supabase via getShippingZones().
export async function getShippingRate(district) {
  try {
    const zones = await (await getStore()).getShippingZones?.() || [];
    if (Array.isArray(zones) && zones.length) {
      const z = zones.find(z => (z.provinces || z.districts || []).includes(district));
      if (z) return z.rate ?? z.shippingRate ?? 350;
    }
  } catch {}
  // Fallback: read from store.js (works in demo mode)
  const store = await getStore();
  if (typeof store.getShippingRate === 'function') return store.getShippingRate(district);
  const colombo = ['Colombo','Gampaha','Kalutara'];
  return colombo.includes(district) ? 250 : 350;
}

export async function getDeliveryDays(district) {
  try {
    const zones = await (await getStore()).getShippingZones?.() || [];
    if (Array.isArray(zones) && zones.length) {
      const z = zones.find(z => (z.provinces || z.districts || []).includes(district));
      if (z) return `${z.min_days||z.minDays||2}–${z.max_days||z.maxDays||4} Business Days`;
    }
  } catch {}
  const store = await getStore();
  if (typeof store.getDeliveryDays === 'function') return store.getDeliveryDays(district);
  const colombo = ['Colombo','Gampaha','Kalutara'];
  return colombo.includes(district) ? '1–2 Business Days' : '2–4 Business Days';
}
