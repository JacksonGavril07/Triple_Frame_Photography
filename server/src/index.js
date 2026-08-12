import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

const app = express();
const port = Number(process.env.PORT || 8787);
const databaseFile = path.resolve(process.env.DATABASE_FILE || './data/triple-frame.sqlite');
fs.mkdirSync(path.dirname(databaseFile), { recursive: true });
const db = new Database(databaseFile);
const jwtSecret = process.env.JWT_SECRET || 'development-only-change-me';

app.use(cors({ origin: process.env.CLIENT_ORIGIN || true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'photographer',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS weekly_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    weekday INTEGER NOT NULL CHECK (weekday BETWEEN 0 AND 6),
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS blocked_times (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    reason TEXT DEFAULT '',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

const publicUser = row => ({ id: row.id, name: row.name, email: row.email, role: row.role, active: Boolean(row.active) });
const tokenFor = user => jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '7d' });
function auth(req, res, next){
  try {
    const token = req.cookies.tf_session || (req.headers.authorization || '').replace('Bearer ', '');
    if(!token) return res.status(401).json({ error: 'Authentication required.' });
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch { res.status(401).json({ error: 'Invalid or expired session.' }); }
}
function adminOnly(req, res, next){
  if(req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}
function validTime(time){ return typeof time === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(time); }
function overlaps(aStart, aEnd, bStart, bEnd){ return (!bStart || !bEnd) || (aStart < bEnd && aEnd > bStart); }

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Run once before using the dashboard. The setup key should be changed in .env.
app.post('/api/setup', (req, res) => {
  if(process.env.ADMIN_SETUP_KEY && req.headers['x-setup-key'] !== process.env.ADMIN_SETUP_KEY) return res.status(403).json({ error: 'Invalid setup key.' });
  if(db.prepare('SELECT COUNT(*) AS count FROM users').get().count > 0) return res.status(409).json({ error: 'Setup has already been completed.' });
  const { photographers = [] } = req.body;
  if(!Array.isArray(photographers) || photographers.length !== 3) return res.status(400).json({ error: 'Provide exactly three photographer profiles.' });
  const insert = db.prepare('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)');
  const created = db.transaction(() => photographers.map((person, index) => insert.run(person.name, person.email.toLowerCase(), bcrypt.hashSync(person.password, 12), index === 0 ? 'admin' : 'photographer')));
  created(photographers);
  res.status(201).json({ message: 'Setup complete. The first profile is the administrator.' });
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email);
  if(!user || !bcrypt.compareSync(String(req.body.password || ''), user.password_hash)) return res.status(401).json({ error: 'Incorrect email or password.' });
  res.cookie('tf_session', tokenFor(user), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 });
  res.json({ user: publicUser(user) });
});
app.post('/api/auth/logout', (_req, res) => { res.clearCookie('tf_session'); res.status(204).end(); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)) }));

app.get('/api/photographers', (_req, res) => {
  res.json(db.prepare('SELECT id,name,email,role,active FROM users WHERE active = 1 ORDER BY id').all().map(publicUser));
});
app.get('/api/admin/photographers', auth, adminOnly, (_req, res) => {
  res.json(db.prepare('SELECT id,name,email,role,active FROM users ORDER BY id').all().map(publicUser));
});
app.patch('/api/admin/photographers/:id', auth, adminOnly, (req, res) => {
  const fields = ['name', 'email', 'active'];
  const updates = fields.filter(field => req.body[field] !== undefined);
  if(!updates.length) return res.status(400).json({ error: 'No profile changes supplied.' });
  const values = updates.map(field => field === 'active' ? (req.body[field] ? 1 : 0) : req.body[field]);
  db.prepare(`UPDATE users SET ${updates.map(field => `${field} = ?`).join(', ')} WHERE id = ?`).run(...values, req.params.id);
  res.json({ ok: true });
});

app.get('/api/schedule/:userId', auth, (req, res) => {
  if(req.user.role !== 'admin' && Number(req.params.userId) !== req.user.id) return res.status(403).json({ error: 'You can only view your own schedule.' });
  res.json({ weekly: db.prepare('SELECT id,weekday,start_time,end_time FROM weekly_schedule WHERE user_id = ? ORDER BY weekday,start_time').all(req.params.userId), blocked: db.prepare('SELECT id,date,start_time,end_time,reason FROM blocked_times WHERE user_id = ? ORDER BY date,start_time').all(req.params.userId) });
});
app.put('/api/schedule/:userId/weekly', auth, (req, res) => {
  const userId = Number(req.params.userId);
  if(req.user.role !== 'admin' && userId !== req.user.id) return res.status(403).json({ error: 'You can only edit your own schedule.' });
  if(!Array.isArray(req.body.entries) || req.body.entries.some(item => !Number.isInteger(item.weekday) || !validTime(item.start_time) || !validTime(item.end_time) || item.start_time >= item.end_time)) return res.status(400).json({ error: 'Use valid weekday and time ranges.' });
  db.transaction(() => { db.prepare('DELETE FROM weekly_schedule WHERE user_id = ?').run(userId); const add = db.prepare('INSERT INTO weekly_schedule (user_id,weekday,start_time,end_time) VALUES (?,?,?,?)'); req.body.entries.forEach(item => add.run(userId,item.weekday,item.start_time,item.end_time)); })();
  res.json({ ok: true });
});
app.post('/api/schedule/:userId/blocked', auth, (req, res) => {
  const userId = Number(req.params.userId);
  if(req.user.role !== 'admin' && userId !== req.user.id) return res.status(403).json({ error: 'You can only edit your own schedule.' });
  const { date, start_time = null, end_time = null, reason = '' } = req.body;
  if(!/^\d{4}-\d{2}-\d{2}$/.test(date) || ((start_time || end_time) && (!validTime(start_time) || !validTime(end_time) || start_time >= end_time))) return res.status(400).json({ error: 'Use a valid date and optional time range.' });
  const result = db.prepare('INSERT INTO blocked_times (user_id,date,start_time,end_time,reason) VALUES (?,?,?,?,?)').run(userId,date,start_time,end_time,reason);
  res.status(201).json({ id: result.lastInsertRowid });
});
app.delete('/api/schedule/blocked/:id', auth, (req, res) => {
  const block = db.prepare('SELECT user_id FROM blocked_times WHERE id = ?').get(req.params.id);
  if(!block || (req.user.role !== 'admin' && block.user_id !== req.user.id)) return res.status(403).json({ error: 'You cannot remove this block.' });
  db.prepare('DELETE FROM blocked_times WHERE id = ?').run(req.params.id); res.status(204).end();
});

// Returns the merged availability of all active photographers.
app.get('/api/availability', (req, res) => {
  const date = String(req.query.date || '');
  const time = String(req.query.time || '');
  const duration = Number(req.query.duration || 60);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'A date is required.' });
  const weekday = new Date(`${date}T12:00:00`).getDay();
  const users = db.prepare('SELECT id,name FROM users WHERE active = 1 ORDER BY id').all();
  const available = users.filter(user => {
    const schedules = db.prepare('SELECT start_time,end_time FROM weekly_schedule WHERE user_id = ? AND weekday = ?').all(user.id, weekday);
    if(time && validTime(time)) {
      const endMinutes = Number(time.slice(0,2))*60 + Number(time.slice(3)) + duration;
      const end = `${String(Math.floor(endMinutes / 60)).padStart(2,'0')}:${String(endMinutes % 60).padStart(2,'0')}`;
      if(!schedules.some(slot => slot.start_time <= time && slot.end_time >= end)) return false;
      const blocks = db.prepare('SELECT start_time,end_time FROM blocked_times WHERE user_id = ? AND date = ?').all(user.id,date);
      return !blocks.some(block => overlaps(time,end,block.start_time,block.end_time));
    }
    return schedules.length > 0 && db.prepare('SELECT 1 FROM blocked_times WHERE user_id = ? AND date = ? AND start_time IS NULL').get(user.id,date) === undefined;
  });
  res.json({ date, availablePhotographers: available, busyCount: users.length - available.length, fullyUnavailable: available.length === 0 });
});

app.listen(port, () => console.log(`Triple Frame schedule API listening on http://localhost:${port}`));
