require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const app = express();
const PORT = 3000;
const SALT = 10;

// ── Database ─────────────────────────────────────────────────
const db = new DatabaseSync(path.join(__dirname, 'database.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    google_id     TEXT,
    created_at    TEXT    DEFAULT (datetime('now', 'localtime'))
  );
  CREATE TABLE IF NOT EXISTS login_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id),
    username     TEXT    NOT NULL,
    logged_in_at TEXT    DEFAULT (datetime('now', 'localtime'))
  );
`);

// Add google_id column if it doesn't exist yet (safe migration)
try { db.exec(`ALTER TABLE users ADD COLUMN google_id TEXT`); } catch (_) { }

// ── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(__dirname));

// ── Passport: Google Strategy ────────────────────────────────
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/callback',
  },
  async (_accessToken, _refreshToken, profile, done) => {
    try {
      const googleId = profile.id;
      const displayName = (profile.displayName || profile.emails?.[0]?.value?.split('@')[0] || 'user').replace(/\s+/g, '_');

      // Try to find existing user by google_id
      let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleId);

      if (!user) {
        // Try to link by username if they previously registered manually
        let username = displayName;
        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existing) username = `${username}_g`; // avoid collision

        const dummyHash = await bcrypt.hash(Math.random().toString(36), SALT);
        const result = db.prepare(
          'INSERT INTO users (username, password_hash, google_id) VALUES (?, ?, ?)'
        ).run(username, dummyHash, googleId);

        user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      }

      db.prepare('INSERT INTO login_logs (user_id, username) VALUES (?, ?)').run(user.id, user.username);
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  done(null, user || false);
});

// ── Google OAuth Routes ──────────────────────────────────────
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?error=google_failed' }),
  (req, res) => {
    const { username, created_at } = req.user;
    res.redirect(`/?user=${encodeURIComponent(username)}&createdAt=${encodeURIComponent(created_at)}`);
  }
);

// ── Register ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: `Username "${username}" is already taken.` });

  const hash = await bcrypt.hash(password, SALT);
  const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
  db.prepare('INSERT INTO login_logs (user_id, username) VALUES (?, ?)').run(result.lastInsertRowid, username);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  return res.status(201).json({ success: true, createdAt: user.created_at });
});

// ── Login ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: `No account found for "${username}". Please register first.` });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect password. Please try again.' });

  db.prepare('INSERT INTO login_logs (user_id, username) VALUES (?, ?)').run(user.id, username);
  return res.json({ success: true, username: user.username, createdAt: user.created_at });
});

// ── Admin: all users with stats ──────────────────────────────
app.get('/api/admin/users', (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.created_at, u.google_id,
           COUNT(l.id) AS login_count,
           MAX(l.logged_in_at) AS last_login
    FROM users u
    LEFT JOIN login_logs l ON l.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all();
  res.json(users);
});

// ── Admin: login history for a user ──────────────────────────
app.get('/api/admin/users/:username/logs', (req, res) => {
  const logs = db.prepare(`
    SELECT logged_in_at FROM login_logs
    WHERE username = ?
    ORDER BY logged_in_at DESC
    LIMIT 50
  `).all(req.params.username);
  res.json(logs);
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  Server running  → http://localhost:${PORT}`);
  console.log(`📊  Admin dashboard → http://localhost:${PORT}/admin.html`);

  if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID === 'your-google-client-id-here') {
    console.warn('\n⚠️  Google OAuth not configured — edit .env with your Client ID & Secret\n');
  } else {
    console.log('🔐  Google OAuth   → enabled');
  }
});
