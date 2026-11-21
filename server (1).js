'use strict';
// Кропивницький 24/7 — бекенд, етап 1: акаунти, ролі, журнал дій. Без залежностей (Node 22+).
const http = require('node:http'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const PORT = +process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || 'data.db';
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const OWNER_EMAIL = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
const ROLES = ['OWNER', 'CO-OWNER', 'ADMIN', 'EDITOR', 'USER'];
const RANK = { 'OWNER': 5, 'CO-OWNER': 4, 'ADMIN': 3, 'EDITOR': 2, 'USER': 1 };
const db = new DatabaseSync(DB_FILE);
db.exec(`create table if not exists users(id integer primary key, email text unique not null, name text not null,
  pass text not null, role text not null default 'USER', created text not null, banned integer not null default 0);
 create table if not exists sessions(token text primary key, user_id integer not null, expires integer not null);
 create table if not exists audit(id integer primary key, ts text not null, actor_id integer, actor_email text, action text not null, target text, details text);
 create table if not exists attempts(k text, ts integer);
 create table if not exists news(id integer primary key, grp text, date text not null, text text not null, html text not null,
  photos text not null default '[]', hidden integer not null default 0, alert integer not null default 0);`);
// ---------- Telegram ----------
const TG_TOKEN = process.env.TG_TOKEN || '', TG_API = process.env.TG_API || 'https://api.telegram.org';
const TG_CHANNEL = (process.env.TG_CHANNEL || 'Kirovohrad_INFO').replace(/^@/, '').toLowerCase();
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
// Повітряні тривоги й відбої на сайт не потрапляють
const ALERT_RE = /повітрян\p{L}*\s+тривог|(^|[^\p{L}])(відб(ій|ою|ої|оя|і)\p{L}*|тривог\p{L}*)|air\s*raid|🚨/iu;
const escH = (t) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function toHtml(text, ents) { // зміщення сутностей Telegram — в UTF-16, як у рядках JS
  const open = {}, close = {};
  for (const e of ents || []) {
    let a = null, b = null;
    if (e.type === 'bold') { a = '<b>'; b = '</b>'; } else if (e.type === 'italic') { a = '<i>'; b = '</i>'; }
    else if (e.type === 'underline') { a = '<u>'; b = '</u>'; }
    else if (e.type === 'text_link' && /^https?:\/\//i.test(e.url || '')) { a = '<a href="' + escH(e.url).replace(/"/g, '&quot;') + '">'; b = '</a>'; }
    if (!a) continue; (open[e.offset] = open[e.offset] || []).push(a); (close[e.offset + e.length] = close[e.offset + e.length] || []).unshift(b);
  }
  let out = ''; for (let i = 0; i <= text.length; i++) { out += (close[i] || []).join('') + (open[i] || []).join(''); if (i < text.length) out += escH(text[i]); }
  return out;
}
function ingest(u) { // u — update від Telegram; повертає true, якщо щось збережено
  const m = u.channel_post || u.edited_channel_post; if (!m || !m.chat) return false;
  if ((m.chat.username || '').toLowerCase() !== TG_CHANNEL && String(m.chat.id) !== process.env.TG_CHANNEL) return false;
  const text = m.text || m.caption || '', ents = m.entities || m.caption_entities || [];
  const photo = m.photo && m.photo.length ? m.photo[m.photo.length - 1].file_id : null;
  const grp = m.media_group_id ? String(m.media_group_id) : null;
  const iso = new Date(m.date * 1000).toISOString();
  const prev = grp ? db.prepare('select * from news where grp=? order by id limit 1').get(grp) : db.prepare('select * from news where id=?').get(m.message_id);
  if (!text.trim() && !photo) return false;
  if (prev) { // альбом або редагування: додаємо фото/оновлюємо текст
    const ph = JSON.parse(prev.photos); if (photo && !ph.includes(photo)) ph.push(photo);
    const t = text.trim() ? text : prev.text, h = text.trim() ? toHtml(text, ents) : prev.html;
    db.prepare('update news set text=?,html=?,photos=?,alert=? where id=?').run(t, h, JSON.stringify(ph), ALERT_RE.test(t) ? 1 : 0, prev.id); return true;
  }
  db.prepare('insert into news(id,grp,date,text,html,photos,alert) values(?,?,?,?,?,?,?)')
    .run(m.message_id, grp, iso, text, toHtml(text, ents), JSON.stringify(photo ? [photo] : []), ALERT_RE.test(text) ? 1 : 0); return true;
}
async function tg(method, params) { const r = await fetch(TG_API + '/bot' + TG_TOKEN + '/' + method, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params || {}) });
  const j = await r.json(); if (!j.ok) throw new Error(j.description || 'telegram'); return j.result; }
async function poll() {
  let offset = 0; try { await tg('deleteWebhook'); } catch (e) { console.error('Telegram:', e.message); }
  for (;;) { try { const ups = await tg('getUpdates', { offset, timeout: 30, allowed_updates: ['channel_post', 'edited_channel_post'] });
      for (const u of ups) { offset = u.update_id + 1; try { ingest(u); } catch (e) { console.error(e.message); } } }
    catch (e) { console.error('Telegram:', e.message); await new Promise(r => setTimeout(r, 5000)); } }
}

const now = () => new Date().toISOString();
const log = (actor, action, target, details) => db.prepare('insert into audit(ts,actor_id,actor_email,action,target,details) values(?,?,?,?,?,?)')
  .run(now(), actor ? actor.id : null, actor ? actor.email : null, action, target || null, details ? JSON.stringify(details) : null);
const hash = (p) => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const verify = (p, h) => { const [s, k] = h.split(':'); const a = crypto.scryptSync(p, Buffer.from(s, 'hex'), 64); return crypto.timingSafeEqual(a, Buffer.from(k, 'hex')); };
const pub = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, created: u.created, banned: !!u.banned });
// Брутфорс: 8 спроб на email+IP за 15 хв
function limited(key) { const t = Date.now() - 9e5; db.prepare('delete from attempts where ts<?').run(t);
  return db.prepare('select count(*) c from attempts where k=?').get(key).c >= 8; }
const fail = (key) => db.prepare('insert into attempts values(?,?)').run(key, Date.now());
function userFrom(req) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || ''); if (!m) return null;
  const th = crypto.createHash('sha256').update(m[1]).digest('hex');
  const s = db.prepare('select * from sessions where token=? and expires>?').get(th, Date.now()); if (!s) return null;
  const u = db.prepare('select * from users where id=?').get(s.user_id); return u && !u.banned ? u : null;
}
function newSession(uid) { const t = crypto.randomBytes(32).toString('hex');
  db.prepare('insert into sessions values(?,?,?)').run(crypto.createHash('sha256').update(t).digest('hex'), uid, Date.now() + 30 * 864e5); return t; }
function body(req) { return new Promise((res, rej) => { let b = ''; req.on('data', c => { b += c; if (b.length > 1e5) { rej(new Error('big')); req.destroy(); } });
  req.on('end', () => { try { res(b ? JSON.parse(b) : {}); } catch (e) { rej(e); } }); }); }
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS', 'Vary': 'Origin', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(obj)); };
const need = (u, min) => u && RANK[u.role] >= RANK[min];

async function handle(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const url = new URL(req.url, 'http://x'), p = url.pathname, ip = req.socket.remoteAddress;
  const me = userFrom(req);
  if (p === '/api/health') return send(res, 200, { ok: true });
  if (req.method === 'POST' && p === '/api/register') {
    const b = await body(req); const email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 60), pw = String(b.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) return send(res, 400, { error: 'Некоректна пошта' });
    if (!name) return send(res, 400, { error: 'Вкажіть імʼя' });
    if (pw.length < 8 || pw.length > 200) return send(res, 400, { error: 'Пароль: мінімум 8 символів' });
    if (db.prepare('select 1 from users where email=?').get(email)) return send(res, 409, { error: 'Ця пошта вже зареєстрована' });
    // Роль завжди USER; єдиний виняток — пошта власника із змінної середовища, і тільки якщо власника ще немає.
    const hasOwner = db.prepare("select 1 from users where role='OWNER'").get();
    const role = (!hasOwner && OWNER_EMAIL && email === OWNER_EMAIL) ? 'OWNER' : 'USER';
    const r = db.prepare('insert into users(email,name,pass,role,created) values(?,?,?,?,?)').run(email, name, hash(pw), role, now());
    const u = db.prepare('select * from users where id=?').get(r.lastInsertRowid); log(u, 'register', email, { role });
    return send(res, 201, { token: newSession(u.id), user: pub(u) });
  }
  if (req.method === 'POST' && p === '/api/login') {
    const b = await body(req); const email = String(b.email || '').trim().toLowerCase(), key = email + '|' + ip;
    if (limited(key)) return send(res, 429, { error: 'Забагато спроб. Спробуйте за 15 хвилин' });
    const u = db.prepare('select * from users where email=?').get(email);
    if (!u || !verify(String(b.password || ''), u.pass) || u.banned) { fail(key); if (u) log(u, 'login_failed', email); return send(res, 401, { error: 'Невірна пошта або пароль' }); }
    log(u, 'login', email); return send(res, 200, { token: newSession(u.id), user: pub(u) });
  }
  if (req.method === 'POST' && p === '/api/logout') { const m = /^Bearer (\S+)$/.exec(req.headers.authorization || '');
    if (m) db.prepare('delete from sessions where token=?').run(crypto.createHash('sha256').update(m[1]).digest('hex')); return send(res, 200, { ok: true }); }
  if (req.method === 'GET' && p === '/api/news') { // публічно; без тривог і прихованих
    const lim = Math.min(100, Math.max(1, +url.searchParams.get('limit') || 50));
    const rows = db.prepare('select * from news where hidden=0 and alert=0 order by date desc limit ?').all(lim);
    return send(res, 200, { items: rows.map(r => ({ id: r.id, text: r.text, html: r.html, date: r.date, link: 'https://t.me/' + (process.env.TG_CHANNEL || 'Kirovohrad_INFO').replace(/^@/, '') + '/' + r.id,
      photos: JSON.parse(r.photos).map(f => PUBLIC_URL + '/api/photo/' + f) })) });
  }
  if (req.method === 'GET' && /^\/api\/photo\/[\w-]+$/.test(p)) { // токен бота ніколи не потрапляє в браузер
    try { const f = await tg('getFile', { file_id: p.split('/').pop() }); const r = await fetch(TG_API + '/file/bot' + TG_TOKEN + '/' + f.file_path);
      if (!r.ok) throw 0; res.writeHead(200, { 'Content-Type': r.headers.get('content-type') || 'image/jpeg', 'Cache-Control': 'public, max-age=86400', 'Access-Control-Allow-Origin': ORIGIN, 'Cross-Origin-Resource-Policy': 'cross-origin' });
      return res.end(Buffer.from(await r.arrayBuffer())); } catch (e) { return send(res, 404, { error: 'Фото недоступне' }); }
  }
  if (!me) return send(res, 401, { error: 'Потрібен вхід' });
  if (req.method === 'GET' && p === '/api/me') return send(res, 200, { user: pub(me) });
  if (req.method === 'POST' && p === '/api/me/password') {
    const b = await body(req); if (!verify(String(b.old || ''), me.pass)) return send(res, 403, { error: 'Старий пароль невірний' });
    if (String(b.new || '').length < 8) return send(res, 400, { error: 'Пароль: мінімум 8 символів' });
    db.prepare('update users set pass=? where id=?').run(hash(String(b.new)), me.id); db.prepare('delete from sessions where user_id=?').run(me.id);
    log(me, 'password_change', me.email); return send(res, 200, { token: newSession(me.id) });
  }
  // --- тільки ADMIN і вище ---
  if (req.method === 'GET' && p === '/api/admin/users') { if (!need(me, 'ADMIN')) return send(res, 403, { error: 'Недостатньо прав' });
    return send(res, 200, { users: db.prepare('select * from users order by id').all().map(pub) }); }
  if (req.method === 'PATCH' && /^\/api\/admin\/users\/\d+$/.test(p)) {
    if (!need(me, 'ADMIN')) return send(res, 403, { error: 'Недостатньо прав' });
    const t = db.prepare('select * from users where id=?').get(+p.split('/').pop()); if (!t) return send(res, 404, { error: 'Не знайдено' });
    const b = await body(req);
    if (t.id === me.id) return send(res, 403, { error: 'Не можна змінювати власний акаунт' });
    if (RANK[t.role] >= RANK[me.role]) return send(res, 403, { error: 'Не можна змінювати користувача зі рівною чи вищою роллю' });
    if (b.role !== undefined) {
      if (!ROLES.includes(b.role) || b.role === 'OWNER') return send(res, 400, { error: 'Недопустима роль' });
      if (RANK[b.role] >= RANK[me.role]) return send(res, 403, { error: 'Не можна призначити роль, рівну чи вищу за власну' });
      db.prepare('update users set role=? where id=?').run(b.role, t.id); log(me, 'role_change', t.email, { from: t.role, to: b.role });
    }
    if (b.banned !== undefined) { db.prepare('update users set banned=? where id=?').run(b.banned ? 1 : 0, t.id);
      if (b.banned) db.prepare('delete from sessions where user_id=?').run(t.id); log(me, b.banned ? 'ban' : 'unban', t.email); }
    return send(res, 200, { user: pub(db.prepare('select * from users where id=?').get(t.id)) });
  }
  if (req.method === 'PATCH' && /^\/api\/admin\/news\/\d+$/.test(p)) { if (!need(me, 'EDITOR')) return send(res, 403, { error: 'Недостатньо прав' });
    const id = +p.split('/').pop(), b = await body(req); if (!db.prepare('select 1 from news where id=?').get(id)) return send(res, 404, { error: 'Не знайдено' });
    db.prepare('update news set hidden=? where id=?').run(b.hidden ? 1 : 0, id); log(me, b.hidden ? 'news_hide' : 'news_show', String(id)); return send(res, 200, { ok: true }); }
  if (req.method === 'GET' && p === '/api/admin/audit') { if (!need(me, 'CO-OWNER')) return send(res, 403, { error: 'Недостатньо прав' });
    return send(res, 200, { audit: db.prepare('select * from audit order by id desc limit 200').all() }); }
  return send(res, 404, { error: 'Не знайдено' });
}
const server = http.createServer((q, s) => handle(q, s).catch(e => send(s, 400, { error: 'Некоректний запит' })));
if (require.main === module) { server.listen(PORT, () => console.log('Listening on ' + PORT)); if (TG_TOKEN) poll(); else console.log('TG_TOKEN не задано: імпорт з Telegram вимкнено'); }
module.exports = server; module.exports.ingest = ingest; module.exports.db = db;
