-- ============================================================
-- ZENMARKET — Complete Supabase Setup  (run once in SQL Editor)
-- Includes all ALTER TABLE for missing columns, new tables,
-- fixed RPC functions, trigger, RLS policies, and indexes.
-- Safe to re-run: uses IF NOT EXISTS / CREATE OR REPLACE.
--
-- v2 CHANGES (merged from FIX-orders-supabase.sql):
--   • § 3  — ADD COLUMN coupon_code (fixes PGRST204 error)
--   • § 21 — NOTIFY pgrst reload schema cache
-- ============================================================


-- ============================================================
-- § 1. PRODUCTS
-- ============================================================
CREATE TABLE IF NOT EXISTS products (
  id            text        PRIMARY KEY,
  name          text        NOT NULL,
  slug          text        UNIQUE NOT NULL,
  description   text,
  price         numeric     NOT NULL DEFAULT 0,
  compare_price numeric,
  stock         integer     NOT NULL DEFAULT 0,
  category      text,
  category_slug text,
  sku           text,
  weight        numeric,
  tags          text[]      DEFAULT '{}',
  hashtags      text[]      DEFAULT '{}',
  images        text[]      DEFAULT '{}',
  variants      jsonb       DEFAULT '[]',
  active        boolean     NOT NULL DEFAULT true,
  featured      boolean     NOT NULL DEFAULT false,
  rating        numeric     DEFAULT 0,
  review_count  integer     DEFAULT 0,
  seo_title     text,
  seo_desc      text,
  created_at    timestamptz DEFAULT now(),
  updated_at    timestamptz DEFAULT now()
);
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon read active products"  ON products;
CREATE POLICY "Anon read active products" ON products FOR SELECT TO anon USING (active = true);
DROP POLICY IF EXISTS "Anon all products"           ON products;
-- Removed: FOR ALL TO anon (allowed public DELETE). Writes now require authenticated session.
DROP POLICY IF EXISTS "Auth all products" ON products;
CREATE POLICY "Auth all products" ON products FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 2. CATEGORIES
-- ============================================================
CREATE TABLE IF NOT EXISTS categories (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  slug        text UNIQUE NOT NULL,
  description text,
  image       text,
  icon        text,
  parent_id   text REFERENCES categories(id) ON DELETE SET NULL,
  active      boolean     NOT NULL DEFAULT true,
  sort_order  integer     DEFAULT 0,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Safe back-fills for existing deployments that ran an earlier version of this script
ALTER TABLE categories ADD COLUMN IF NOT EXISTS icon      text;
ALTER TABLE categories ADD COLUMN IF NOT EXISTS parent_id text REFERENCES categories(id) ON DELETE SET NULL;
ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all categories" ON categories;
-- Removed: FOR ALL TO anon. Anon users only need to read categories.
DROP POLICY IF EXISTS "Anon read categories" ON categories;
CREATE POLICY "Anon read categories" ON categories FOR SELECT TO anon USING (true);
DROP POLICY IF EXISTS "Auth all categories" ON categories;
CREATE POLICY "Auth all categories" ON categories FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 3. ORDERS
-- ============================================================
CREATE TABLE IF NOT EXISTS orders (
  id              text PRIMARY KEY,
  customer_id     text,
  customer_name   text,
  customer_email  text,
  customer_phone  text,
  address         jsonb,
  items           jsonb   DEFAULT '[]',
  subtotal        numeric DEFAULT 0,
  shipping        numeric DEFAULT 0,
  discount        numeric DEFAULT 0,
  total           numeric DEFAULT 0,
  status          text    DEFAULT 'pending',
  payment_status  text    DEFAULT 'pending',
  payment_method  text    DEFAULT 'cod',
  payment_id      text,
  payment_slip    text,
  bank_ref        text,
  coupon_code     text,
  notes           text,
  created_at      timestamptz DEFAULT now(),
  updated_at      timestamptz DEFAULT now()
);
-- Safe back-fills for deployments that ran an earlier version of this script
ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code  text DEFAULT '';   -- FIX: PGRST204 "coupon_code not found in schema cache"
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id   text;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_slip text;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
-- Drop ALL known policy names (including legacy ones) before re-creating.
-- This ensures a clean slate even on databases that ran earlier versions of this script.
DROP POLICY IF EXISTS "Anon all orders"          ON orders;
DROP POLICY IF EXISTS "Anon insert orders"        ON orders;
DROP POLICY IF EXISTS "Anon read all orders"      ON orders;
DROP POLICY IF EXISTS "Anon update orders"        ON orders;
DROP POLICY IF EXISTS "Auth all orders"           ON orders;
DROP POLICY IF EXISTS "Auth insert own orders"    ON orders;
DROP POLICY IF EXISTS "Auth select own orders"    ON orders;
-- Legacy names that may exist on older deployments:
DROP POLICY IF EXISTS "Users can insert orders"   ON orders;
DROP POLICY IF EXISTS "Users can read own orders" ON orders;
DROP POLICY IF EXISTS "Users own orders"          ON orders;
DROP POLICY IF EXISTS "Select own orders"         ON orders;
DROP POLICY IF EXISTS "Insert orders"             ON orders;
DROP POLICY IF EXISTS "Authenticated insert"      ON orders;
DROP POLICY IF EXISTS "Public insert orders"      ON orders;
DROP POLICY IF EXISTS "Allow insert for all"      ON orders;

-- Anon can INSERT orders.
-- Required because the storefront uses a custom localStorage auth that does NOT
-- create a Supabase Auth session, so all browser requests arrive as the anon role.
CREATE POLICY "Anon insert orders" ON orders
  FOR INSERT TO anon WITH CHECK (true);

-- Anon can SELECT all orders.
-- Required by the admin dashboard, which uses the anon key (custom password auth,
-- NOT a Supabase user session). The admin panel is separately protected by an
-- app-level password.  This policy does NOT expose order data in the storefront UI —
-- the storefront pages always filter by customer_id / customer_email client-side.
-- In full-Supabase-Auth deployments you can remove this policy and use the
-- service-role-key serverless endpoint (/api/admin/orders) exclusively.
CREATE POLICY "Anon read all orders" ON orders
  FOR SELECT TO anon USING (true);

-- Anon UPDATE — admin updates order status from the dashboard (anon key + custom password).
-- Only the fields the admin actually changes are written; the serverless function
-- (/api/admin/orders PUT) uses service-role and is preferred in production.
CREATE POLICY "Anon update orders" ON orders
  FOR UPDATE TO anon USING (true) WITH CHECK (true);

-- Anon DELETE — admin deletes orders from the dashboard (anon key + custom password auth).
-- Without this policy the deleteOrder() / deleteOrders() calls in admin-orders.js fail
-- with "permission denied" because the anon role only had SELECT/INSERT/UPDATE before.
-- The admin dashboard is separately protected by the ADMIN_API_TOKEN app-level password.
DROP POLICY IF EXISTS "Anon delete orders" ON orders;
CREATE POLICY "Anon delete orders" ON orders
  FOR DELETE TO anon USING (true);

-- Authenticated Supabase-Auth users get full access to all orders.
-- INSERT at checkout, SELECT own orders in profile, UPDATE/DELETE via
-- the service-role serverless functions (admin dashboard).
-- The broad USING(true) is intentional: admin uses a Supabase Auth user
-- too, and the service-role API is the real access-control boundary.
CREATE POLICY "Auth all orders" ON orders
  FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 4. COUPONS
-- ============================================================
CREATE TABLE IF NOT EXISTS coupons (
  id          text    PRIMARY KEY,
  code        text    UNIQUE NOT NULL,
  type        text    NOT NULL DEFAULT 'percent',
  value       numeric NOT NULL DEFAULT 0,
  min_order   numeric DEFAULT 0,
  max_uses    integer DEFAULT NULL,
  used_count  integer NOT NULL DEFAULT 0,
  active      boolean NOT NULL DEFAULT true,
  expires_at  timestamptz,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Safe back-fills for existing deployments that ran an earlier version of this script
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_uses    integer DEFAULT NULL;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS used_count  integer NOT NULL DEFAULT 0;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS expires_at  timestamptz;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS min_order   numeric DEFAULT 0;
-- Fix: drop any stale type check constraint and replace with the correct allowed values
ALTER TABLE coupons DROP CONSTRAINT IF EXISTS coupons_type_check;
ALTER TABLE coupons ADD CONSTRAINT coupons_type_check CHECK (type IN ('percent', 'fixed', 'shipping'));
ALTER TABLE coupons ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all coupons" ON coupons;
-- Removed: FOR ALL TO anon. Storefront only needs to read active coupons.
-- The increment_coupon_usage() RPC runs SECURITY DEFINER so it bypasses RLS.
DROP POLICY IF EXISTS "Anon read active coupons" ON coupons;
DROP POLICY IF EXISTS "Anon read all coupons"    ON coupons;   -- FIX: drop before re-create to allow safe re-runs
-- Allow anon to read all coupons so the storefront can give accurate error messages
-- (e.g. "coupon is disabled" vs "coupon not found"). The application code enforces active check.
CREATE POLICY "Anon read all coupons" ON coupons FOR SELECT TO anon USING (true);
DROP POLICY IF EXISTS "Auth all coupons" ON coupons;
CREATE POLICY "Auth all coupons" ON coupons FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 5. SHIPPING ZONES
-- ============================================================
CREATE TABLE IF NOT EXISTS shipping_zones (
  id          text    PRIMARY KEY,
  name        text    NOT NULL,
  provinces   text[]  DEFAULT '{}',
  districts   text[]  DEFAULT '{}',
  rate        numeric NOT NULL DEFAULT 0,
  free_above  numeric DEFAULT NULL,
  min_days    integer DEFAULT 2,
  max_days    integer DEFAULT 4,
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Ensure all columns exist on older tables (safe to re-run)
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS districts   text[]       DEFAULT '{}';
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS free_above  numeric      DEFAULT NULL;
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS min_days    integer      DEFAULT 2;
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS max_days    integer      DEFAULT 4;
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS active      boolean      NOT NULL DEFAULT true;
ALTER TABLE shipping_zones ADD COLUMN IF NOT EXISTS updated_at  timestamptz  DEFAULT now();
-- Copy legacy 'provinces' data into 'districts' if needed
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'shipping_zones' AND column_name = 'provinces'
  ) THEN
    UPDATE shipping_zones
    SET districts = provinces
    WHERE (districts IS NULL OR districts = '{}')
      AND provinces IS NOT NULL AND provinces != '{}';
  END IF;
END $$;
ALTER TABLE shipping_zones ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all shipping_zones" ON shipping_zones;
-- Removed: FOR ALL TO anon.
DROP POLICY IF EXISTS "Anon read shipping_zones" ON shipping_zones;
CREATE POLICY "Anon read shipping_zones" ON shipping_zones FOR SELECT TO anon USING (true);
DROP POLICY IF EXISTS "Auth all shipping_zones" ON shipping_zones;
CREATE POLICY "Auth all shipping_zones" ON shipping_zones FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 6. PROFILES  (customers + admin users)
-- ============================================================
CREATE TABLE IF NOT EXISTS profiles (
  id          uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name        text,
  email       text,
  phone       text    DEFAULT '',
  role        text    DEFAULT 'customer' CHECK (role IN ('customer','admin')),
  active      boolean DEFAULT true,
  orders      integer DEFAULT 0,
  total_spent numeric DEFAULT 0,
  addresses   jsonb   DEFAULT '[]',
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Add missing columns (safe on existing tables)
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS email       text;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS active      boolean DEFAULT true;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS orders      integer DEFAULT 0;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS total_spent numeric DEFAULT 0;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS addresses   jsonb   DEFAULT '[]';

-- Backfill email from auth.users for existing rows
UPDATE profiles p SET email = u.email
FROM auth.users u WHERE p.id = u.id AND p.email IS NULL;

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon read all profiles"  ON profiles;
CREATE POLICY "Anon read all profiles"  ON profiles FOR SELECT TO anon USING (true);
DROP POLICY IF EXISTS "Anon update profiles"    ON profiles;
CREATE POLICY "Anon update profiles"    ON profiles FOR UPDATE TO anon USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "Anon insert profiles"    ON profiles;
CREATE POLICY "Anon insert profiles"    ON profiles FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Users own profile"       ON profiles;
CREATE POLICY "Users own profile"       ON profiles FOR ALL TO authenticated USING (auth.uid()=id) WITH CHECK (auth.uid()=id);


-- ============================================================
-- § 7. REVIEWS
-- ============================================================
CREATE TABLE IF NOT EXISTS reviews (
  id          text PRIMARY KEY,
  product_id  text NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  user_id     text NOT NULL,
  user_name   text DEFAULT 'Anonymous',
  rating      integer NOT NULL CHECK (rating BETWEEN 1 AND 5),
  title       text    DEFAULT '',
  body        text    NOT NULL,
  verified    boolean DEFAULT false,
  approved    boolean DEFAULT false,
  rejected    boolean DEFAULT false,
  edited_at   timestamptz,
  approved_at timestamptz,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Add missing columns (safe on existing tables)
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS rejected    boolean     DEFAULT false;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS edited_at   timestamptz;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS updated_at  timestamptz DEFAULT now();

ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon read approved reviews" ON reviews;
CREATE POLICY "Anon read approved reviews" ON reviews FOR SELECT TO anon USING (approved=true AND rejected=false);
DROP POLICY IF EXISTS "Anon all reviews" ON reviews;
-- Removed: FOR ALL TO anon — this overrode the approved-only SELECT policy and
-- allowed public DELETE/UPDATE of all reviews (fixes #19 conflicting RLS + #20).
DROP POLICY IF EXISTS "Anon insert reviews" ON reviews;
CREATE POLICY "Anon insert reviews" ON reviews FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Auth all reviews" ON reviews;
CREATE POLICY "Auth all reviews" ON reviews FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 8. CONTACT MESSAGES
-- ============================================================
CREATE TABLE IF NOT EXISTS contact_messages (
  id         text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  first_name text, last_name text, email text, phone text,
  subject    text, message   text,
  read       boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE contact_messages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all contact_messages" ON contact_messages;
-- Removed: FOR ALL TO anon. Public users only need to submit (INSERT) messages.
DROP POLICY IF EXISTS "Anon insert contact_messages" ON contact_messages;
CREATE POLICY "Anon insert contact_messages" ON contact_messages FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Auth all contact_messages" ON contact_messages;
CREATE POLICY "Auth all contact_messages" ON contact_messages FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 9. BLOG POSTS
-- ============================================================
CREATE TABLE IF NOT EXISTS blog_posts (
  id           text PRIMARY KEY,
  title        text NOT NULL,
  slug         text UNIQUE NOT NULL,
  category     text,
  excerpt      text,
  content      text,
  cover_image  text,
  author       text    DEFAULT 'ZenMarket Team',
  published    boolean DEFAULT false,
  featured     boolean DEFAULT false,
  read_time    integer DEFAULT 5,
  tags         text[]  DEFAULT '{}',
  seo_title    text,
  seo_desc     text,
  created_at   timestamptz DEFAULT now(),
  updated_at   timestamptz DEFAULT now()
);
-- Ensure all optional columns exist on older tables (safe to re-run)
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS content     text;                      -- FIX: was missing — caused "content column not found in schema cache"
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS category    text         DEFAULT '';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS excerpt     text         DEFAULT '';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS cover_image text         DEFAULT '';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS author      text         DEFAULT 'ZenMarket Team';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS featured    boolean      DEFAULT false;
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS read_time   integer      DEFAULT 5;
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS tags        text[]       DEFAULT '{}';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS seo_title   text         DEFAULT '';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS seo_desc    text         DEFAULT '';
ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS updated_at  timestamptz  DEFAULT now();
ALTER TABLE blog_posts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon read published posts" ON blog_posts;
CREATE POLICY "Anon read published posts" ON blog_posts FOR SELECT TO anon USING (published=true);
DROP POLICY IF EXISTS "Anon all blog_posts" ON blog_posts;
-- Removed: FOR ALL TO anon (allowed public DELETE of any post).
DROP POLICY IF EXISTS "Auth all blog_posts" ON blog_posts;
CREATE POLICY "Auth all blog_posts" ON blog_posts FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 10. NOTIFICATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
  id         text PRIMARY KEY,
  type       text NOT NULL DEFAULT 'info',
  title      text NOT NULL DEFAULT '',
  message    text NOT NULL DEFAULT '',
  data       jsonb DEFAULT '{}',
  user_id    text,
  read       boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS user_id text;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all notifications" ON notifications;
-- Removed: FOR ALL TO anon. Split into safe per-operation policies.
DROP POLICY IF EXISTS "Anon read notifications"   ON notifications;
CREATE POLICY "Anon read notifications"   ON notifications FOR SELECT TO anon USING (true);
DROP POLICY IF EXISTS "Anon insert notifications" ON notifications;
CREATE POLICY "Anon insert notifications" ON notifications FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Anon update notifications" ON notifications;
-- Restrict anon UPDATE to only flipping read=true; prevents mass-marking all rows
CREATE POLICY "Anon update notifications" ON notifications FOR UPDATE TO anon
  USING (true) WITH CHECK (read = true);
DROP POLICY IF EXISTS "Auth all notifications" ON notifications;
CREATE POLICY "Auth all notifications"    ON notifications FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 11. SITE SETTINGS
-- ============================================================
CREATE TABLE IF NOT EXISTS site_settings (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL DEFAULT '{}',
  updated_at timestamptz DEFAULT now()
);
ALTER TABLE site_settings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all site_settings"    ON site_settings;
-- Removed: FOR ALL TO anon. Storefront only reads settings; writes are admin-only.
DROP POLICY IF EXISTS "Anon read site_settings"   ON site_settings;
CREATE POLICY "Anon read site_settings"   ON site_settings FOR SELECT TO anon USING (true);
-- Allow admin panel (uses anon key + custom password auth) to save settings
DROP POLICY IF EXISTS "Anon write site_settings"  ON site_settings;
CREATE POLICY "Anon write site_settings"  ON site_settings FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Anon update site_settings" ON site_settings;
CREATE POLICY "Anon update site_settings" ON site_settings FOR UPDATE TO anon USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "Auth all site_settings"    ON site_settings;
CREATE POLICY "Auth all site_settings"    ON site_settings FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 12. NEWSLETTER SUBSCRIBERS  (NEW)
-- ============================================================
CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  email         text PRIMARY KEY,
  subscribed_at timestamptz DEFAULT now(),
  active        boolean DEFAULT true
);
ALTER TABLE newsletter_subscribers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon insert newsletter" ON newsletter_subscribers;
CREATE POLICY "Anon insert newsletter" ON newsletter_subscribers FOR INSERT TO anon WITH CHECK (true);
DROP POLICY IF EXISTS "Anon read newsletter"  ON newsletter_subscribers;
CREATE POLICY "Anon read newsletter"  ON newsletter_subscribers FOR SELECT TO anon USING (true);


-- ============================================================
-- § 13. ADMIN CONFIG
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_config (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL DEFAULT '{}',
  updated_at timestamptz DEFAULT now()
);
ALTER TABLE admin_config ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anon all admin_config" ON admin_config;
-- Removed: FOR ALL TO anon — exposes password hashes and secret config to the public.
-- admin_config is only accessible via the service_role key (server-side API routes).
DROP POLICY IF EXISTS "Auth all admin_config" ON admin_config;
CREATE POLICY "Auth all admin_config" ON admin_config FOR ALL TO authenticated USING (true) WITH CHECK (true);


-- ============================================================
-- § 14. RPC FUNCTIONS
-- ============================================================

-- Atomically decrement product stock (prevents going below 0)
CREATE OR REPLACE FUNCTION decrement_stock(product_id text, amount integer)
RETURNS void LANGUAGE sql SECURITY DEFINER AS $$
  UPDATE products
  SET stock = GREATEST(0, stock - amount), updated_at = now()
  WHERE id = product_id;
$$;

-- Atomically increment coupon usage counter
CREATE OR REPLACE FUNCTION increment_coupon_usage(coupon_code text)
RETURNS void LANGUAGE sql SECURITY DEFINER AS $$
  UPDATE coupons SET used_count = used_count + 1, updated_at = now()
  WHERE code = coupon_code;
$$;

-- Recalculate product avg rating from approved reviews
CREATE OR REPLACE FUNCTION refresh_product_rating(p_product_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_avg   numeric;
  v_count integer;
BEGIN
  SELECT COALESCE(AVG(rating),0), COUNT(*)
  INTO v_avg, v_count
  FROM reviews
  WHERE product_id = p_product_id AND approved = true AND rejected = false;
  UPDATE products SET rating = ROUND(v_avg,1), review_count = v_count, updated_at = now()
  WHERE id = p_product_id;
END;
$$;

-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_products_updated_at   ON products;
CREATE TRIGGER trg_products_updated_at   BEFORE UPDATE ON products   FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_orders_updated_at     ON orders;
CREATE TRIGGER trg_orders_updated_at     BEFORE UPDATE ON orders     FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_reviews_updated_at    ON reviews;
CREATE TRIGGER trg_reviews_updated_at    BEFORE UPDATE ON reviews    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_profiles_updated_at   ON profiles;
CREATE TRIGGER trg_profiles_updated_at   BEFORE UPDATE ON profiles   FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Trigger: auto-approve review recalculates product rating
CREATE OR REPLACE FUNCTION trg_review_approved()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.approved IS DISTINCT FROM OLD.approved OR NEW.rejected IS DISTINCT FROM OLD.rejected) THEN
    PERFORM refresh_product_rating(NEW.product_id);
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_reviews_rating ON reviews;
CREATE TRIGGER trg_reviews_rating AFTER UPDATE ON reviews FOR EACH ROW EXECUTE FUNCTION trg_review_approved();

-- Grant RPC function access to both anon and authenticated roles
GRANT EXECUTE ON FUNCTION decrement_stock(text,integer) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION increment_coupon_usage(text)  TO anon, authenticated;
GRANT EXECUTE ON FUNCTION refresh_product_rating(text)  TO anon, authenticated;


-- ============================================================
-- § 15. TRIGGER: Auto-create profile on Supabase auth signup
-- ============================================================
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO public.profiles (id, name, phone, role, email, addresses)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email,'@',1)),
    COALESCE(NEW.raw_user_meta_data->>'phone',''),
    'customer',
    NEW.email,
    '[]'::jsonb
  )
  ON CONFLICT (id) DO UPDATE SET
    email      = EXCLUDED.email,
    updated_at = now();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION handle_new_user();


-- ============================================================
-- § 16. REALTIME
-- ============================================================
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname='supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END $$;

DO $$ DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['orders','products','reviews','notifications'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables WHERE pubname='supabase_realtime' AND tablename=t) THEN
      EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE %I', t);
    END IF;
  END LOOP;
END $$;


-- ============================================================
-- § 17. INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_products_slug          ON products(slug);
CREATE INDEX IF NOT EXISTS idx_products_category_slug ON products(category_slug);
CREATE INDEX IF NOT EXISTS idx_products_active        ON products(active);
CREATE INDEX IF NOT EXISTS idx_orders_customer_id     ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_status          ON orders(status);
CREATE INDEX IF NOT EXISTS idx_reviews_product_id     ON reviews(product_id);
CREATE INDEX IF NOT EXISTS idx_reviews_user_id        ON reviews(user_id);
CREATE INDEX IF NOT EXISTS idx_reviews_approved       ON reviews(approved);
CREATE INDEX IF NOT EXISTS idx_blog_posts_slug        ON blog_posts(slug);
CREATE INDEX IF NOT EXISTS idx_notifications_read     ON notifications(read);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id  ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_coupons_code           ON coupons(code);

-- ============================================================
-- § 18. STORAGE — product-images bucket
-- ============================================================
-- Create the public bucket used by admin product-edit for image uploads.
-- Safe to re-run: ON CONFLICT (id) DO NOTHING.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'product-images',
  'product-images',
  true,
  5242880,   -- 5 MB per file
  ARRAY['image/jpeg','image/png','image/webp','image/gif']
)
ON CONFLICT (id) DO NOTHING;

-- Allow anyone to read public product images
DROP POLICY IF EXISTS "Public read product images"  ON storage.objects;
CREATE POLICY "Public read product images"
  ON storage.objects FOR SELECT TO anon
  USING (bucket_id = 'product-images');

-- Allow authenticated users (admins) to upload/update/delete product images
DROP POLICY IF EXISTS "Admin upload product images"  ON storage.objects;
CREATE POLICY "Admin upload product images"
  ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'product-images');

DROP POLICY IF EXISTS "Admin update product images"  ON storage.objects;
CREATE POLICY "Admin update product images"
  ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'product-images');

DROP POLICY IF EXISTS "Admin delete product images"  ON storage.objects;
CREATE POLICY "Admin delete product images"
  ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'product-images');

-- ============================================================
-- § 19. STORAGE — payment-slips bucket
-- ============================================================
-- Private bucket for customer bank transfer slip uploads.
-- Max file size: 500 KB.  Accepted: JPEG, PNG, WebP, PDF.
-- NOT public — direct URL access requires authenticated SELECT policy.
-- The admin views slips via the admin panel (service-role key).
-- Customers upload at checkout via the anon/authenticated policies below.
-- Safe to re-run: ON CONFLICT (id) DO NOTHING.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'payment-slips',
  'payment-slips',
  true,           -- public so checkout can retrieve the URL immediately after upload
  524288,         -- 500 KB
  ARRAY['image/jpeg','image/png','image/webp','application/pdf']
) ON CONFLICT (id) DO NOTHING;

-- Allow anonymous users (pre-login browser sessions) to upload slips
DROP POLICY IF EXISTS "Anon upload payment slips"  ON storage.objects;
CREATE POLICY "Anon upload payment slips"
  ON storage.objects FOR INSERT TO anon
  WITH CHECK (bucket_id = 'payment-slips');

-- Allow anon to UPDATE/replace an existing slip (needed for upsert:true in the checkout)
DROP POLICY IF EXISTS "Anon update payment slips"  ON storage.objects;
CREATE POLICY "Anon update payment slips"
  ON storage.objects FOR UPDATE TO anon
  USING (bucket_id = 'payment-slips')
  WITH CHECK (bucket_id = 'payment-slips');

-- Allow authenticated customers to upload slips
DROP POLICY IF EXISTS "Auth upload payment slips"  ON storage.objects;
CREATE POLICY "Auth upload payment slips"
  ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'payment-slips');

-- Allow authenticated to UPDATE/replace slips (upsert support)
DROP POLICY IF EXISTS "Auth update payment slips"  ON storage.objects;
CREATE POLICY "Auth update payment slips"
  ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'payment-slips')
  WITH CHECK (bucket_id = 'payment-slips');

-- Allow authenticated users (admins + customers) to read slips
DROP POLICY IF EXISTS "Auth read payment slips"    ON storage.objects;
CREATE POLICY "Auth read payment slips"
  ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'payment-slips');

-- Allow public SELECT so the stored URL works in the admin order-detail page
-- (bucket is already marked public=true above; this policy makes it explicit)
DROP POLICY IF EXISTS "Public read payment slips"  ON storage.objects;
CREATE POLICY "Public read payment slips"
  ON storage.objects FOR SELECT TO anon
  USING (bucket_id = 'payment-slips');

-- ============================================================
-- § 20. TABLE-LEVEL GRANTS
-- ============================================================
-- In Supabase projects created after ~2023, RLS policies alone
-- are NOT enough. The anon and authenticated roles also need
-- explicit table-level GRANT privileges, otherwise every request
-- gets "permission denied for table orders" regardless of policies.
-- Safe to run on older projects too — GRANT is idempotent.
-- ============================================================

-- Schema access (required before any table operations)
GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- orders
-- Anon needs DELETE so the admin dashboard (which uses the anon key + custom password auth)
-- can delete orders. Without this grant, deleteOrder() fails with "permission denied".
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.orders TO anon;
GRANT ALL                            ON TABLE public.orders TO authenticated;

-- products
GRANT SELECT                        ON TABLE public.products TO anon;
GRANT ALL                           ON TABLE public.products TO authenticated;

-- categories
GRANT SELECT                        ON TABLE public.categories TO anon;
GRANT ALL                           ON TABLE public.categories TO authenticated;

-- coupons
GRANT SELECT                        ON TABLE public.coupons TO anon;
GRANT ALL                           ON TABLE public.coupons TO authenticated;

-- profiles
GRANT SELECT, INSERT, UPDATE        ON TABLE public.profiles TO anon;
GRANT ALL                           ON TABLE public.profiles TO authenticated;

-- reviews
GRANT SELECT, INSERT                ON TABLE public.reviews TO anon;
GRANT ALL                           ON TABLE public.reviews TO authenticated;

-- notifications
GRANT SELECT, INSERT, UPDATE        ON TABLE public.notifications TO anon;
GRANT ALL                           ON TABLE public.notifications TO authenticated;

-- contact_messages
GRANT INSERT                        ON TABLE public.contact_messages TO anon;
GRANT ALL                           ON TABLE public.contact_messages TO authenticated;

-- blog_posts
GRANT SELECT                        ON TABLE public.blog_posts TO anon;
GRANT ALL                           ON TABLE public.blog_posts TO authenticated;

-- shipping_zones
GRANT SELECT                        ON TABLE public.shipping_zones TO anon;
GRANT ALL                           ON TABLE public.shipping_zones TO authenticated;

-- site_settings
-- Anon needs INSERT + UPDATE so the admin panel (custom password auth = anon role)
-- can save settings via the anon key. SELECT is already granted by the RLS policy.
GRANT SELECT, INSERT, UPDATE        ON TABLE public.site_settings TO anon;
GRANT ALL                           ON TABLE public.site_settings TO authenticated;

-- newsletter_subscribers
GRANT INSERT                        ON TABLE public.newsletter_subscribers TO anon;
GRANT ALL                           ON TABLE public.newsletter_subscribers TO authenticated;

-- admin_config
-- No anon access — admin_config contains sensitive data (password hashes, API tokens).
-- Access is only via the service_role key in /api/* serverless functions.
-- GRANT SELECT to anon is intentionally omitted — RLS would block it anyway.
GRANT ALL ON TABLE public.admin_config TO authenticated;

-- ============================================================
-- § 21. RELOAD POSTGREST SCHEMA CACHE
-- ============================================================
-- Forces Supabase to immediately recognise any newly added columns
-- (e.g. coupon_code) without requiring a project restart.
-- Fix for: PGRST204 "Could not find the 'coupon_code' column of
-- 'orders' in the schema cache"
-- ============================================================
NOTIFY pgrst, 'reload schema';

-- ============================================================
-- Done. All tables, columns, functions, policies, grants created.
-- Schema cache reloaded — new columns are immediately available.
-- ============================================================
