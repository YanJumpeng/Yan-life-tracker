const { createHash, timingSafeEqual } = require('node:crypto');

// Phase 1: verify authenticated access before connecting any personal data.
module.exports = function handler(req, res) {
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
  return res.status(200).json({
    status: 'ok',
    mode: 'connection_test',
    personal_data_connected: false,
    message: 'Authenticated read access works. No personal records are connected yet.'
  });
};
