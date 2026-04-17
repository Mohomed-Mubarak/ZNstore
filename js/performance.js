/* ============================================================
   ZENMARKET — PERFORMANCE  (PageSpeed 90+ toolkit)
   ============================================================
   • WebP URL helper (Unsplash / Supabase Storage)
   • Lazy-load observer for dynamically injected images
   • Interaction-based deferred loading (analytics, chat widgets)
   • Prefetch next-page on link hover
   ============================================================ */

// ── 1. WebP URL Helper ────────────────────────────────────────
/**
 * Convert an image URL to its WebP-optimised equivalent.
 * Supports Unsplash and Supabase Storage transforms.
 * Falls back to the original URL if the format is unknown.
 *
 * @param {string} url   Original image URL
 * @param {number} w     Desired width in px (default 600)
 * @param {number} q     Quality 1-100 (default 80)
 * @returns {string}     WebP-optimised URL
 */
export function toWebP(url, w = 600, q = 80) {
  if (!url) return url;

  // Unsplash → append format=webp, w, q
  if (url.includes('images.unsplash.com')) {
    const u = new URL(url);
    u.searchParams.set('fm',   'webp');
    u.searchParams.set('w',    String(w));
    u.searchParams.set('q',    String(q));
    u.searchParams.set('fit',  'crop');
    return u.toString();
  }

  // Supabase Storage — the /render/image/ transform endpoint requires
  // Supabase Pro / image-transformation add-on. Calling it on free-tier
  // returns a JSON error, which the browser blocks via ORB (Opaque Response
  // Blocking) when the request comes from an <img> tag.
  // Safe fix: always serve the plain /storage/v1/object/public/ URL.
  // If the URL was already rewritten to a render URL, convert it back.
  if (url.includes('supabase.co/storage')) {
    return url
      .replace('/storage/v1/render/image/public/', '/storage/v1/object/public/')
      .replace(/[?&](width|quality|format)=[^&]*/g, '')
      .replace(/[?&]$/, '');
  }

  // Already a data URI or non-transformable URL — return as-is
  return url;
}

// ── 2. Lazy-load Observer ─────────────────────────────────────
/**
 * Observe <img> elements with data-src and swap src on viewport entry.
 * Call this after injecting new product cards into the DOM.
 *
 * @param {HTMLElement} root  Parent element to scope the search
 */
export function lazyObserve(root = document) {
  if (!('IntersectionObserver' in window)) {
    // Fallback: load everything immediately
    root.querySelectorAll('img[data-src]').forEach(img => {
      img.src = img.dataset.src;
      img.removeAttribute('data-src');
    });
    return;
  }

  const io = new IntersectionObserver((entries, obs) => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const img = entry.target;
      img.src = img.dataset.src;
      img.removeAttribute('data-src');
      img.classList.add('img-loaded');
      obs.unobserve(img);
    });
  }, { rootMargin: '200px' });   // start loading 200px before viewport

  root.querySelectorAll('img[data-src]').forEach(img => io.observe(img));
}

// ── 3. Interaction-based Deferred Loading ────────────────────
/**
 * Defer non-critical third-party scripts (analytics, chat)
 * until the first user interaction (click, scroll, keydown).
 *
 * @param {Function} loader  Function that injects the script tags
 */
export function deferOnInteraction(loader) {
  const events = ['click', 'scroll', 'keydown', 'touchstart', 'mousemove'];
  function onInteract() {
    events.forEach(e => window.removeEventListener(e, onInteract));
    loader();
  }
  events.forEach(e => window.addEventListener(e, onInteract, { once: true, passive: true }));
}

// ── 4. Link Prefetch on Hover ─────────────────────────────────
/**
 * Prefetch a page URL on hover to make navigation feel instant.
 * Only prefetches once per URL and respects Save-Data header.
 *
 * @param {string} selector  CSS selector for <a> elements
 */
export function prefetchOnHover(selector = 'a[href]') {
  if (navigator.connection?.saveData) return;  // respect data-saver mode

  const prefetched = new Set();

  document.addEventListener('mouseover', e => {
    const link = e.target.closest(selector);
    if (!link) return;
    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript') || prefetched.has(href)) return;
    prefetched.add(href);

    const el = document.createElement('link');
    el.rel  = 'prefetch';
    el.href = href;
    document.head.appendChild(el);
  });
}

// ── 5. Critical CSS Inliner Helper ───────────────────────────
/**
 * Mark a <link rel="stylesheet"> as non-render-blocking using
 * the media trick. Call for non-critical CSS files.
 *
 * Usage in HTML:
 *   <link rel="stylesheet" href="animations.css" media="print" onload="this.media='all'">
 *
 * This JS helper does the same dynamically.
 *
 * @param {string} href  CSS file URL to load asynchronously
 */
export function loadCSSAsync(href) {
  const link    = document.createElement('link');
  link.rel      = 'stylesheet';
  link.href     = href;
  link.media    = 'print';
  link.onload   = () => { link.media = 'all'; };
  document.head.appendChild(link);
}

// ── 6. Fast-click: Remove 300ms tap delay on mobile ──────────
export function initFastClick() {
  if ('ontouchstart' in window) {
    document.documentElement.style.setProperty('touch-action', 'manipulation');
  }
}

// ── 7. Responsive image srcset builder ───────────────────────
export function buildSrcset(url, q = 75) {
  if (!url || !url.includes('unsplash.com')) return '';
  const widths = [320, 480, 640, 900, 1200];
  return widths.map(w => `${toWebP(url, w, q)} ${w}w`).join(', ');
}

// ── 8. Adaptive quality by connection ────────────────────────
export function adaptiveQuality() {
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (!conn) return 75;
  if (conn.saveData) return 40;
  const map = { 'slow-2g': 40, '2g': 50, '3g': 65, '4g': 80 };
  return map[conn.effectiveType] ?? 75;
}

// ── 9. Scroll restoration ─────────────────────────────────────
export function initScrollRestoration() {
  if ('scrollRestoration' in history) history.scrollRestoration = 'auto';
}

// ── 10. Safe-area insets for notch devices ────────────────────
export function initSafeArea() {
  const meta = document.querySelector('meta[name="viewport"]');
  if (meta && !meta.content.includes('viewport-fit')) {
    meta.content += ', viewport-fit=cover';
  }
}

// ── 11. Auto-init on module load ─────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    prefetchOnHover();
    initFastClick();
    initScrollRestoration();
    initSafeArea();
  });
} else {
  prefetchOnHover();
  initFastClick();
  initScrollRestoration();
  initSafeArea();
}
