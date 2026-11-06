const crypto = require('node:crypto');

const reply = (res, status, body) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.status(status).json(body);
};

function bodyOf(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body);
  return {};
}

function passwordMatches(candidate, expected) {
  if (!candidate || !expected) return false;
  const a = crypto.createHash('sha256').update(String(candidate)).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function config() {
  const url = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  return { url, key, adminPassword: process.env.ADMIN_PASSWORD || '' };
}

function supabaseHeaders(key, extra = {}) {
  return { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', ...extra };
}

module.exports = async (req, res) => {
  const { url, key, adminPassword } = config();
  if (!url || !key || !adminPassword) {
    return reply(res, 503, { error: 'ยังตั้งค่า SUPABASE_URL, SUPABASE_SECRET_KEY และ ADMIN_PASSWORD ใน Vercel ไม่ครบ' });
  }

  const tableUrl = `${url}/rest/v1/portfolio_content`;

  if (req.method === 'GET') {
    try {
      const db = await fetch(`${tableUrl}?id=eq.main&select=data`, {
        headers: supabaseHeaders(key),
      });
      if (!db.ok) {
        const detail = await db.text();
        console.error('Supabase read failed:', db.status, detail);
        return reply(res, 502, { error: 'อ่านข้อมูลจาก Supabase ไม่สำเร็จ ตรวจตารางและ API key' });
      }
      const rows = await db.json();
      if (!rows.length) return reply(res, 404, { error: 'ยังไม่มีข้อมูลในฐานข้อมูล' });
      return reply(res, 200, rows[0].data);
    } catch (error) {
      console.error('Supabase read error:', error);
      return reply(res, 502, { error: 'เชื่อมต่อ Supabase ไม่สำเร็จ' });
    }
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return reply(res, 405, { error: 'Method not allowed' });
  }

  let body;
  try {
    body = bodyOf(req);
  } catch {
    return reply(res, 400, { error: 'รูปแบบข้อมูลไม่ถูกต้อง' });
  }

  const suppliedPassword = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!passwordMatches(suppliedPassword, adminPassword)) {
    return reply(res, 401, { error: 'รหัสผู้ดูแลไม่ถูกต้อง' });
  }

  if (body.action === 'auth') return reply(res, 200, { authenticated: true });
  if (body.action !== 'save' || !body.data || !Array.isArray(body.data.projects) || !body.data.profile) {
    return reply(res, 400, { error: 'ข้อมูลที่ส่งมาไม่ครบ' });
  }

  const payloadSize = Buffer.byteLength(JSON.stringify(body.data), 'utf8');
  if (payloadSize > 3.5 * 1024 * 1024) {
    return reply(res, 413, { error: 'ข้อมูลและรูปภาพใหญ่เกินกำหนด กรุณาลดขนาดหรือลดจำนวนรูปภาพ' });
  }

  try {
    const db = await fetch(`${tableUrl}?on_conflict=id`, {
      method: 'POST',
      headers: supabaseHeaders(key, { Prefer: 'resolution=merge-duplicates,return=minimal' }),
      body: JSON.stringify({
        id: 'main',
        data: body.data,
        updated_at: new Date().toISOString(),
      }),
    });
    if (!db.ok) {
      const detail = await db.text();
      console.error('Supabase write failed:', db.status, detail);
      return reply(res, 502, { error: 'บันทึกลงฐานข้อมูลไม่สำเร็จ ตรวจ SQL และสิทธิ์ Supabase' });
    }
    return reply(res, 200, { saved: true, updatedAt: new Date().toISOString() });
  } catch (error) {
    console.error('Supabase write error:', error);
    return reply(res, 502, { error: 'เชื่อมต่อ Supabase ไม่สำเร็จ' });
  }
};
