require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

const root = __dirname;
const dataDir = path.join(root, 'data');
const uploadDir = path.join(root, 'uploads');
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'sandy.db'), { enableForeignKeyConstraints: true });
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('audio', 'image', 'video')),
    title TEXT NOT NULL,
    artist TEXT,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    is_visible INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function seedUser(username, password, role) {
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  const hashedPassword = bcrypt.hashSync(password, 12);
  
  if (!user) {
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, hashedPassword, role);
  } else {
    db.prepare('UPDATE users SET password_hash = ?, role = ? WHERE id = ?')
      .run(hashedPassword, role, user.id);
  }
}

seedUser(process.env.SANDY_USERNAME || 'sandy', process.env.SANDY_PASSWORD || '1234', 'user');
seedUser(process.env.ADMIN_USERNAME || 'admin', process.env.ADMIN_PASSWORD || 'change-me-now', 'admin');
seedUser(process.env.THIRD_USERNAME || 'private-user', process.env.THIRD_PASSWORD || 'change-this-too', 'user');

const app = express();
app.disable('x-powered-by');
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000 * 60 * 60 * 24 * 14 }
}));

const allowed = {
  audio: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4', 'audio/x-m4a'],
  image: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
  video: ['video/mp4', 'video/webm', 'video/quicktime']
};
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({ storage, limits: { fileSize: 150 * 1024 * 1024 } });

function publicUser(user) { return { id: user.id, username: user.username, role: user.role }; }
function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'يرجى تسجيل الدخول أولًا.' }); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'هذه الصلاحية للإدارة فقط.' }); next(); }
function mediaPayload(row) { return { ...row, is_visible: Boolean(row.is_visible), url: `/uploads/${encodeURIComponent(row.filename)}` }; }
function safeDelete(filename) { if (filename) fs.unlink(path.join(uploadDir, filename), () => {}); }

app.get('/uploads/:filename', requireAuth, (req, res) => {
  const media = db.prepare('SELECT * FROM media WHERE filename = ?').get(req.params.filename);
  if (!media || (req.session.user.role !== 'admin' && media.owner_id !== req.session.user.id) || !media.is_visible && req.session.user.role !== 'admin') return res.sendStatus(404);
  res.sendFile(path.join(uploadDir, media.filename));
});

app.post('/api/auth/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'اسم المستخدم أو كلمة السر غير صحيحين.' });
  req.session.user = publicUser(user);
  res.json({ user: req.session.user });
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.clearCookie('connect.sid').json({ ok: true })));
app.get('/api/auth/me', (req, res) => res.json({ user: req.session.user || null }));

app.get('/api/media', requireAuth, (req, res) => {
  const type = req.query.type;
  if (type && !Object.hasOwn(allowed, type)) return res.status(400).json({ error: 'نوع غير مدعوم.' });
  const ownOnly = req.session.user.role !== 'admin';
  const sql = `SELECT media.*, users.username AS owner_name FROM media JOIN users ON users.id = media.owner_id WHERE is_visible = 1 ${ownOnly ? 'AND owner_id = ?' : ''} ${type ? 'AND type = ?' : ''} ORDER BY id DESC`;
  const params = [...(ownOnly ? [req.session.user.id] : []), ...(type ? [type] : [])];
  res.json({ media: db.prepare(sql).all(...params).map(mediaPayload) });
});

// السطور من 116 إلى 125 تم تحديثها هنا لدعم رفع ملفات متعددة (حتى 10 ملفات معاً)
app.post('/api/media', requireAuth, upload.array('files', 10), (req, res) => {
  const type = String(req.body.type || '');
  if (!Object.hasOwn(allowed, type)) {
    if (req.files) req.files.forEach(f => safeDelete(f.filename));
    return res.status(400).json({ error: 'نوع غير مدعوم.' });
  }

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'اختَر ملفًا واحدًا على الأقل لرفعه.' });
  }

  const savedMedia = [];
  const errors = [];

  for (const file of req.files) {
    if (!allowed[type].includes(file.mimetype)) {
      safeDelete(file.filename);
      errors.push(`الملف "${file.originalname}" غير متوافق.`);
      continue;
    }

    const title = String(req.body.title || path.parse(file.originalname).name).trim().slice(0, 120) || 'بدون عنوان';
    const artist = String(req.body.artist || '').trim().slice(0, 120);

    try {
      const result = db.prepare('INSERT INTO media (owner_id, type, title, artist, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(req.session.user.id, type, title, artist || null, file.filename, file.originalname, file.mimetype, file.size);
      
      const inserted = db.prepare('SELECT * FROM media WHERE id = ?').get(result.lastInsertRowid);
      savedMedia.push(mediaPayload(inserted));
    } catch (dbErr) {
      safeDelete(file.filename);
      errors.push(`فشل حفظ الملف "${file.originalname}".`);
    }
  }

  if (savedMedia.length === 0) {
    return res.status(400).json({ error: 'لم يتم رفع أي ملف بنجاح.', details: errors });
  }

  res.status(201).json({ success: true, media: savedMedia });
});

app.delete('/api/media/:id', requireAuth, (req, res) => {
  const media = db.prepare('SELECT * FROM media WHERE id = ?').get(req.params.id);
  if (!media) return res.status(404).json({ error: 'الملف غير موجود.' });
  if (req.session.user.role !== 'admin' && media.owner_id !== req.session.user.id) return res.status(403).json({ error: 'لا يمكنك حذف هذا الملف.' });
  db.prepare('DELETE FROM media WHERE id = ?').run(media.id);
  safeDelete(media.filename);
  res.json({ ok: true });
});
app.get('/api/admin/media', requireAdmin, (_, res) => {
  const rows = db.prepare('SELECT media.*, users.username AS owner_name FROM media JOIN users ON users.id = media.owner_id ORDER BY media.id DESC').all();
  res.json({ media: rows.map(mediaPayload) });
});
app.patch('/api/admin/media/:id', requireAdmin, (req, res) => {
  const media = db.prepare('SELECT * FROM media WHERE id = ?').get(req.params.id);
  if (!media) return res.status(404).json({ error: 'الملف غير موجود.' });
  const title = typeof req.body.title === 'string' ? req.body.title.trim().slice(0, 120) : media.title;
  const isVisible = typeof req.body.is_visible === 'boolean' ? Number(req.body.is_visible) : media.is_visible;
  db.prepare('UPDATE media SET title = ?, is_visible = ? WHERE id = ?').run(title || media.title, isVisible, media.id);
  res.json({ media: mediaPayload(db.prepare('SELECT * FROM media WHERE id = ?').get(media.id)) });
});
app.use('/api', (err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'حجم الملف أكبر من 150MB.' : 'تعذّر رفع الملف.' });
  console.error(err); res.status(500).json({ error: 'حدث خطأ في الخادم.' });
});
app.use(express.static(path.join(root, 'public')));
app.get('*', (_, res) => res.sendFile(path.join(root, 'public', 'index.html')));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Sandy site is running at http://localhost:${port}`));
