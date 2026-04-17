/* ============================================================
   ZENMARKET — HOME PAGE
   ============================================================ */
import { withLoader } from './loader.js';
import { injectLayout } from './layout.js';
import { getProducts, getCategories, getSiteSettings, saveNewsletterSubscriber } from './store-adapter.js';
import { getAllReviews, getAllReviewsFlat } from './reviews.js';
import { formatPrice } from './utils.js';
import { addToCart, toggleWishlist, isWishlisted } from './cart.js';
import { initQuickSearch } from './search.js';

function esc(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
import { productCardHTML, bindCardEvents } from './product-card.js';
import toast from './toast.js';
import { LS } from './config.js';

withLoader(async () => {
  await injectLayout({ activePage: 'Home' });
  // Pre-fetch both in parallel — all render functions reuse these
  const [_allProducts, _allCategories] = await Promise.all([
    getProducts(),
    getCategories(),
  ]);
  initHeroParticles();
  renderCategories(_allCategories);
  renderFeatured(_allProducts);
  renderNewArrivals(_allProducts);
  initHeroRotation(_allProducts);
  initQuickSearch(
    document.getElementById('hero-search-input'),
    document.getElementById('search-dropdown')
  );
  document.getElementById('hero-search-btn')?.addEventListener('click', () => {
    const q = document.getElementById('hero-search-input')?.value.trim();
    if (q) window.location.href = `search.html?q=${encodeURIComponent(q)}`;
  });
  await initCountdown();
  await renderHomepageReviews();
  initNewsletter();
});

// ── Categories ────────────────────────────────────────────────
function renderCategories(cats) {
  const grid = document.getElementById('categories-grid');
  if (!grid) return;
  const active = (cats || []).filter(c => c.active !== false);
  grid.innerHTML = active.map(c => `
    <a href="shop.html?cat=${c.slug}" class="cat-card hover-lift">
      <i class="${c.icon}"></i>
      <span>${c.name}</span>
      <small>${c.subcategories?.length ? `${c.subcategories.length} subcategories` : 'View all'}</small>
    </a>`).join('');
}

// ── Featured Products ─────────────────────────────────────────
function renderFeatured(products) {
  const grid = document.getElementById('featured-products');
  if (!grid) return;
  const featured = (products || []).filter(p => p.featured && p.active !== false).slice(0, 4);
  grid.innerHTML = featured.map(p => { try { return productCardHTML(p); } catch { return ''; } }).join('');
  bindCardEvents(grid, products || [], addToCart, toggleWishlist);
}

// ── New Arrivals ──────────────────────────────────────────────
function renderNewArrivals(products) {
  const grid = document.getElementById('new-arrivals');
  if (!grid) return;
  const arrivals = (products || [])
    .filter(p => p.active !== false && p.badge !== 'Used')
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 5);
  grid.innerHTML = arrivals.map(p => { try { return productCardHTML(p); } catch { return ''; } }).join('');
  bindCardEvents(grid, products || [], addToCart, toggleWishlist);
}

// ── Hero product rotation ─────────────────────────────────────
function initHeroRotation(products) {
  const active = (products || []).filter(p => p.active !== false && p.images?.length);
  if (!active.length) return;

  // Prefer featured products, but fall back to all active products with images
  const pool = active.filter(p => p.featured).length >= 2
    ? active.filter(p => p.featured)
    : active;

  let idx = 0;
  const imgEl = document.getElementById('hero-product-img');
  const nameEl = document.getElementById('hero-badge-name');
  const priceEl = document.getElementById('hero-badge-price');
  if (!imgEl) return;

  // ── Immediately show the first Supabase product ──
  const setProduct = (p) => {
    imgEl.src = p.images?.[0] || '';
    imgEl.alt = p.name || 'Product';
    imgEl.style.opacity = '1';
    if (nameEl) nameEl.textContent = p.name;
    if (priceEl) priceEl.textContent = formatPrice(p.price);
  };
  setProduct(pool[0]);

  // ── Don't rotate if only one product ──
  if (pool.length < 2) return;

  const update = () => {
    idx = (idx + 1) % pool.length;
    const p = pool[idx];

    // Fade out → swap src → fade in
    imgEl.style.opacity = '0';
    setTimeout(() => setProduct(p), 400);
  };

  setInterval(update, 5000);
}

// ── Countdown Timer ───────────────────────────────────────────
async function initCountdown() {
  // Load promo settings from Supabase (production) or localStorage (demo)
  let settings = {};
  try { settings = await getSiteSettings().catch(() => null) || {}; } catch {
    try { settings = JSON.parse(localStorage.getItem('zm_site_settings') || '{}'); } catch { }
  }
  const _g = (k, d) => { const v = settings[k]; if (v == null) return d; return (typeof v === 'object' && 'v' in v) ? v.v : v; };

  // Defaults
  const promoEnabled = _g('promoEnabled', true) !== false && _g('promoEnabled', true) !== 'false';
  const eyebrow = _g('promoEyebrow', 'Limited Time Offer');
  const title = _g('promoTitle', 'Mega Sale — Up to 30% Off');
  const desc = _g('promoDesc', "Don't miss out on our biggest sale of the season. Premium products at unbeatable prices.");
  const btnText = _g('promoBtnText', 'Shop the Sale');
  const btnUrl = _g('promoBtnUrl', 'shop.html');
  const endDateStr = _g('promoEndDate', '');

  // Update banner text content
  const sectionEl = document.getElementById('promo-section');
  if (!sectionEl) return;

  if (!promoEnabled) {
    sectionEl.style.display = 'none';
    return;
  }

  const eyebrowEl = document.getElementById('promo-eyebrow-text');
  const titleEl = document.getElementById('promo-title-text');
  const descEl = document.getElementById('promo-desc-text');
  const btnEl = document.getElementById('promo-btn-link');

  if (eyebrowEl) eyebrowEl.textContent = eyebrow;
  if (titleEl) titleEl.textContent = title;
  if (descEl) descEl.textContent = desc;
  if (btnEl) { btnEl.textContent = btnText; btnEl.href = btnUrl; }

  // Determine end time
  const TIMER_KEY = 'zm_promo_timer_end';
  let end;
  if (endDateStr) {
    end = new Date(endDateStr).getTime();
  } else {
    end = parseInt(sessionStorage.getItem(TIMER_KEY) || '0', 10);
    if (!end || end < Date.now()) {
      end = Date.now() + 24 * 60 * 60 * 1000;
      sessionStorage.setItem(TIMER_KEY, String(end));
    }
  }

  const tick = () => {
    const diff = Math.max(0, end - Date.now());
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    const s = Math.floor((diff % 60000) / 1000);
    const pad = n => String(n).padStart(2, '0');
    const hEl = document.getElementById('timer-h');
    const mEl = document.getElementById('timer-m');
    const sEl = document.getElementById('timer-s');
    if (hEl) hEl.textContent = pad(h);
    if (mEl) mEl.textContent = pad(m);
    if (sEl) sEl.textContent = pad(s);
    // When timer hits zero, show "Sale Ended"
    if (diff === 0) {
      const timerWrap = document.getElementById('promo-timer-wrap');
      if (timerWrap) timerWrap.innerHTML = '<span style="color:var(--clr-text-3);font-size:.875rem">Sale has ended</span>';
    }
  };
  tick();
  const _timerId = setInterval(tick, 1000);
  // Clean up if the section is ever removed (e.g. SPA navigation)
  window.addEventListener('pagehide', () => clearInterval(_timerId), { once: true });
}

// ── Newsletter ────────────────────────────────────────────────
function initNewsletter() {
  const form = document.getElementById('newsletter-form');
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const email = (document.getElementById('newsletter-email').value || '').trim().toLowerCase();
    if (!email) return;

    try {
      await saveNewsletterSubscriber(email);
      toast.success('Subscribed!', email + ' added to our newsletter.');
    } catch {
      // Fallback: localStorage demo/offline
      let subs = [];
      try { subs = JSON.parse(localStorage.getItem(LS.newsletterEmails) || '[]'); } catch { }
      if (!subs.find(s => s.email === email)) {
        subs.unshift({ email, subscribedAt: new Date().toISOString() });
        localStorage.setItem(LS.newsletterEmails, JSON.stringify(subs));
        toast.success('Subscribed!', email + ' added to our newsletter.');
      } else { toast.info('Already subscribed', email + ' is already on our newsletter.'); }
    }
    form.reset();
  });
}

// ── Homepage Reviews ──────────────────────────────────────────
async function renderHomepageReviews() {
  const section = document.getElementById('reviews-section');
  if (!section) return;

  // Load homepage reviews config saved by admin
  let cfg = {};
  try {
    const allSettings = await getSiteSettings();
    const raw = allSettings['zm_homepage_reviews'];
    if (raw) cfg = (typeof raw === 'object' && 'v' in raw) ? raw.v : raw;
  } catch { }
  if (!cfg || !Object.keys(cfg).length) { try { cfg = JSON.parse(localStorage.getItem('zm_homepage_reviews') || '{}'); } catch { } }

  // Default to enabled — admin can disable from the reviews panel
  const enabled = cfg.enabled !== false && cfg.enabled !== 'false';
  if (!enabled) { section.style.display = 'none'; return; }

  // Auto-save enabled=true on first load so the admin panel reflects the live state
  if (cfg.enabled === undefined) {
    try {
      const defaultCfg = { enabled: true, title: 'What Our Customers Say', subtitle: 'Real experiences from real shoppers', maxCount: 3, showCta: false };
      localStorage.setItem('zm_homepage_reviews', JSON.stringify(defaultCfg));
      Object.assign(cfg, defaultCfg);
    } catch { }
  }

  // Update editable heading / subtitle
  const titleEl = document.getElementById('reviews-section-title');
  const subtitleEl = document.getElementById('reviews-section-subtitle');
  const ctaEl = document.getElementById('reviews-section-cta');
  if (titleEl && cfg.title) titleEl.textContent = cfg.title;
  if (subtitleEl && cfg.subtitle) subtitleEl.textContent = cfg.subtitle;
  if (ctaEl && cfg.ctaText) {
    ctaEl.textContent = cfg.ctaText + ' ';
    ctaEl.insertAdjacentHTML('beforeend', '<i class="fa-solid fa-arrow-right"></i>');
  }
  if (ctaEl) ctaEl.style.display = cfg.showCta ? '' : 'none';

  // ── Load approved reviews from BOTH stores ──────────────────
  // 1. Admin-curated reviews (zm_admin_reviews)
  let adminReviews = [];
  try {
    const allS = await getSiteSettings();
    const raw = allS['zm_admin_reviews'];
    if (raw) adminReviews = (typeof raw === 'object' && 'v' in raw) ? raw.v : raw;
  } catch { }
  if (!Array.isArray(adminReviews) || !adminReviews.length) { try { adminReviews = JSON.parse(localStorage.getItem('zm_admin_reviews') || '[]'); } catch { } }
  if (!adminReviews.length) { adminReviews = []; }
  const approvedAdmin = adminReviews.filter(r => r.status === 'approved');

  // 2. User-submitted product reviews — approved by admin (works in both Demo + Live/Supabase)
  const approvedProduct = [];
  try {
    const flatReviews = await getAllReviewsFlat();
    let productLookup = {};
    try {
      const prods = await getProducts();
      prods.forEach(p => { productLookup[p.id] = p.name; });
    } catch (e) { console.warn('renderHomepageReviews getProducts:', e); }

    flatReviews.forEach(r => {
      if (r.approved === true) {
        approvedProduct.push({
          id: r.id,
          customer: r.userName || r.user_name || 'Anonymous',
          product: productLookup[r.productId || r.product_id] || r.productId || '',
          rating: r.rating,
          text: r.text || r.body || '',
          date: r.createdAt || r.created_at,
          status: 'approved',
        });
      }
    });
  } catch (e) { console.warn('renderHomepageReviews getAllReviewsFlat:', e); }

  // Merge: admin reviews first, then user-submitted; newest first
  let allReviews = [...approvedAdmin, ...approvedProduct]
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  // Filter to approved only, then optionally to featured IDs
  let approved = allReviews.filter(r => r.status === 'approved');
  if (cfg.featuredIds && cfg.featuredIds.length) {
    const featured = approved.filter(r => cfg.featuredIds.includes(r.id));
    if (featured.length) approved = featured;
  }

  // Limit count
  const maxCount = parseInt(cfg.maxCount, 10) || 3;
  approved = approved.slice(0, maxCount);

  if (!approved.length) { section.style.display = 'none'; return; }

  function starsHtml(n) {
    return Array.from({ length: 5 }, (_, i) =>
      `<i class="fa-${i < n ? 'solid' : 'regular'} fa-star"></i>`
    ).join('');
  }

  function avatarLetter(name) {
    return (name || '?').trim()[0].toUpperCase();
  }

  function formatDate(d) {
    try {
      return new Date(d).toLocaleDateString('en-LK', { day: 'numeric', month: 'short', year: 'numeric' });
    } catch { return d; }
  }

  const grid = document.getElementById('homepage-reviews-grid');
  if (!grid) return;

  grid.innerHTML = approved.map(r => `
    <div class="review-card reveal">
      <div class="review-card__stars">${starsHtml(r.rating)}</div>
      <p class="review-card__text">${esc(r.text)}</p>
      <div class="review-card__footer">
        <div class="review-card__avatar">${avatarLetter(r.customer)}</div>
        <div>
          <div class="review-card__author">${esc(r.customer)}</div>
          <div class="review-card__product">${esc(r.product)}</div>
        </div>
        <span class="review-card__date">${formatDate(r.date)}</span>
      </div>
    </div>`).join('');

  section.style.display = '';
}

// ── Hero Particle Animation ─────────────────────────────────────
async function initHeroParticles() {
  const isMobile = window.matchMedia('(max-width: 768px)').matches;
  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ── 2. Canvas particle field ──────────────────────────────────
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;

  // Continuous rAF loop — skip on mobile to free CPU/GPU for LCP/FID
  if (isMobile || prefersReduced) {
    canvas.style.display = 'none';
    return;
  }

  const hero = canvas.closest('.hero');
  const resize = () => { canvas.width = hero.offsetWidth; canvas.height = hero.offsetHeight; };
  resize();
  window.addEventListener('resize', resize, { passive: true });

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const COLORS = [
    'rgba(201,168,76,',
    'rgba(226,192,110,',
    'rgba(160,122,48,',
    'rgba(255,255,255,',
  ];

  // Scale particle count to device capability
  const particleCount = (navigator.hardwareConcurrency ?? 4) >= 4 ? 90 : 40;

  const particles = Array.from({ length: particleCount }, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    radius: 0.5 + Math.random() * 1.8,
    color: COLORS[Math.floor(Math.random() * COLORS.length)],
    vx: (Math.random() - 0.5) * 0.3,
    vy: -0.08 - Math.random() * 0.35,
    alpha: 0,
    maxAlpha: 0.1 + Math.random() * 0.22,
    fadeIn: true,
    life: 0,
    maxLife: 200 + Math.random() * 320,
    delay: Math.random() * 180,
  }));

  let frame = 0;
  const draw = () => {
    frame++;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => {
      if (frame < p.delay) return;
      p.life++;
      if (p.fadeIn) {
        p.alpha = Math.min(p.alpha + 0.007, p.maxAlpha);
        if (p.alpha >= p.maxAlpha) p.fadeIn = false;
      } else {
        p.alpha -= 0.004;
      }
      if (p.alpha <= 0 || p.life > p.maxLife) {
        p.x = Math.random() * canvas.width;
        p.y = canvas.height + 5;
        p.alpha = 0; p.fadeIn = true; p.life = 0;
        p.maxLife = 200 + Math.random() * 320;
      }
      p.x += p.vx; p.y += p.vy;
      if (p.x < -5) p.x = canvas.width + 5;
      if (p.x > canvas.width + 5) p.x = -5;
      if (p.alpha <= 0) return;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color + p.alpha.toFixed(3) + ')';
      ctx.fill();
    });
    requestAnimationFrame(draw);
  };
  requestAnimationFrame(draw);
}

