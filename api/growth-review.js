const { createHash, timingSafeEqual } = require('node:crypto');

// Only fixed, user-scoped database views are queried. No client-supplied SQL.
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('CDN-Cache-Control', 'no-store');
  res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  const secret = process.env.GROWTH_REVIEW_TOKEN;
  if (!secret || secret.length < 32) {
    return res.status(503).json({ error: 'not_configured' });
  }
  const authorization = req.headers.authorization;
  const provided = typeof authorization === 'string' && authorization.startsWith('Bearer ')
    ? authorization.slice(7) : '';
  const hash = value => createHash('sha256').update(value).digest();
  if (!provided || !timingSafeEqual(hash(provided), hash(secret))) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  let config;
  try {
    const url = new URL(process.env.GROWTH_REVIEW_DATABASE_URL);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) ||
        url.hostname !== 'aws-1-ap-northeast-2.pooler.supabase.com' ||
        url.port !== '6543' || url.pathname !== '/postgres' ||
        decodeURIComponent(url.username) !== 'growth_review_reader.mkzuggwwkobupbuiggxm' ||
        !url.password || url.search || url.hash) {
      throw new Error('Invalid database configuration');
    }
    config = {
      host: url.hostname, port: 6543, database: 'postgres',
      user: decodeURIComponent(url.username), password: decodeURIComponent(url.password),
      ssl: {
        rejectUnauthorized: true,
        ...(process.env.GROWTH_REVIEW_DB_CA
          ? { ca: process.env.GROWTH_REVIEW_DB_CA.replace(/\\n/g, '\n') } : {})
      },
      connectionTimeoutMillis: 8000,
      query_timeout: 10000,
      application_name: 'growth-review-readonly'
    };
  } catch {
    return res.status(503).json({ error: 'database_not_configured' });
  }

  let client;
  try {
    const { Client } = require('pg');
    client = new Client(config);
    await client.connect();
    await client.query('BEGIN READ ONLY');
    await client.query("SET LOCAL statement_timeout = '8000ms'");
    await client.query("SET LOCAL TIME ZONE 'Asia/Shanghai'");
    const daily = await client.query('SELECT * FROM growth_review_private.daily ORDER BY date ASC LIMIT 30');
    const weekly = await client.query('SELECT * FROM growth_review_private.weekly ORDER BY year DESC, wk DESC LIMIT 8');
    const plan = await client.query('SELECT * FROM growth_review_private.plan LIMIT 1');
    await client.query('COMMIT');
    return res.status(200).json({
      status: 'ok', mode: 'growth_review', personal_data_connected: true,
      generated_at: new Date().toISOString(), timezone: 'Asia/Shanghai',
      scope: { daily_days: 30, weekly_max_rows: 8, plan_max_rows: 1, journals_included: false },
      counts: { daily: daily.rows.length, weekly: weekly.rows.length, plan: plan.rows.length },
      daily: daily.rows, weekly: weekly.rows, plan: plan.rows
    });
  } catch (error) {
    if (client) { try { await client.query('ROLLBACK'); } catch {} }
    // Never expose database messages, connection strings or record contents.
    const code = error && error.code;
    const safeErrors = {
      '28P01': 'database_auth_failed', '42501': 'database_permission_denied',
      '42P01': 'database_views_missing', '57014': 'database_timeout',
      SELF_SIGNED_CERT_IN_CHAIN: 'database_tls_certificate_error',
      UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'database_tls_certificate_error',
      CERT_HAS_EXPIRED: 'database_tls_certificate_error',
      DEPTH_ZERO_SELF_SIGNED_CERT: 'database_tls_certificate_error'
    };
    return res.status(502).json({ error: safeErrors[code] || 'database_unavailable' });
  } finally {
    if (client) { try { await client.end(); } catch {} }
  }
};
