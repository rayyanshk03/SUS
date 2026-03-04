# SUS — Secure User System

A lightweight local authentication server with username/password login and Google OAuth 2.0 sign-in, built with Node.js, Express, and SQLite.

---

## Features

- 🔐 Username & password registration / login
- 🔵 Google OAuth 2.0 ("Continue with Google")
- 🗄️ SQLite database (no setup required)
- 📊 Admin dashboard with login history
- 🔒 Passwords hashed with bcrypt

---

## Project Structure

```
SUS/
├── server.js       # Express backend + Passport OAuth
├── index.html      # Login / Register page
├── admin.html      # Admin dashboard
├── database.db     # SQLite database (auto-created)
├── .env            # Google credentials (do NOT commit)
├── .gitignore
└── package.json
```

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Configure Google OAuth

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → **APIs & Services → Credentials**
2. Create an **OAuth 2.0 Client ID** (Web application)
3. Add this to **Authorized redirect URIs**:
   ```
   http://localhost:3000/auth/google/callback
   ```
4. Add this to **Authorized JavaScript origins**:
   ```
   http://localhost:3000
   ```
5. Copy your **Client ID** and **Client Secret**

### 3. Fill in `.env`

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
SESSION_SECRET=any-random-string
```

### 4. Start the server

```bash
node server.js
```

---

## Usage

| URL | Page |
|-----|------|
| `http://localhost:3000` | Login / Register |
| `http://localhost:3000/admin.html` | Admin dashboard |

### Admin Dashboard

Shows every registered user with:
- Username & registration date
- Total login count
- Last login timestamp
- Full login history (click any row to expand)

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/register` | Register with username + password |
| `POST` | `/api/login` | Login with username + password |
| `GET` | `/auth/google` | Start Google OAuth flow |
| `GET` | `/auth/google/callback` | Google OAuth callback |
| `GET` | `/api/admin/users` | List all users with stats |
| `GET` | `/api/admin/users/:username/logs` | Login history for a user |

---

## Database Schema

```sql
users (id, username, password_hash, google_id, created_at)
login_logs (id, user_id, username, logged_in_at)
```

Google-authenticated users have a `google_id` set. Their passwords are a random bcrypt hash (never used for login).

---

## Security Notes

- `.env` is gitignored — never commit your credentials
- Passwords are hashed with bcrypt (10 salt rounds)
- Sessions are in-memory — users re-login after server restart
- This is designed for **local / development use**
