# 🔐 Secure File Vault

A production-grade secure file storage system with enterprise authentication, RBAC, and end-to-end encryption.

## Architecture

```
secure-file-vault/
├── backend/          # Node.js/Express API (Member A — Auth & Backend Core)
│   ├── auth/         # JWT, MFA, sessions, password reset
│   ├── rbac/         # Role hierarchy + ABAC policies
│   ├── admin/        # Admin routes + audit streaming
│   ├── audit/        # Immutable audit logs + SIEM-compatible
│   ├── links/        # HMAC-signed expiring download links
│   └── config/       # DB, Redis, env
├── frontend/         # React + Vite (Member B)
├── security/         # ClamAV + YARA rules (Member C)
├── infra/            # Docker, nginx, compose
└── docs/             # API docs, architecture, security
```

## Member Responsibilities

| Member | Area | Key Features |
|--------|------|-------------|
| **A** | Auth & Backend Core | JWT/JWKS, RTR, bcrypt/Argon2id, TOTP MFA, RBAC+ABAC, Redis rate limiter, Audit logs |
| B | Frontend & Security | React UI, CSP, DOMPurify, Trusted Types |
| C | Upload & Scanning | ClamAV, YARA, encryption, polyglot detection |

## Quick Start

```bash
# 1. Clone and install
cd backend && npm install

# 2. Copy env
cp .env.example .env

# 3. Start with Docker
cd infra && docker-compose up -d

# 4. Backend only (dev)
cd backend && npm run dev
```

## Environment Variables

```env
MONGO_URI=mongodb://localhost:27017/secure-vault
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-secret-here
JWT_ALGORITHM=HS256          # or RS256
BCRYPT_ROUNDS=12
PASSWORD_ALGO=bcrypt         # or argon2id
MFA_ISSUER=SecureVault
MFA_BACKUP_ENCRYPTION_KEY=32-char-key-here
RESET_TOKEN_SECRET=reset-secret
CSRF_SECRET=csrf-secret
SIGNED_LINK_SECRET=link-secret
FRONTEND_URL=http://localhost:3000
```

## API Endpoints (Member A)

### Auth (`/auth/*`)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register user |
| POST | `/auth/login` | Login + optional TOTP |
| POST | `/auth/refresh` | RTR token refresh |
| POST | `/auth/logout` | Logout (blacklist token) |
| POST | `/auth/logout-all` | Revoke all sessions |
| GET  | `/auth/me` | Get current user |
| POST | `/auth/mfa/setup` | Generate TOTP QR |
| POST | `/auth/mfa/verify` | Enable MFA |
| DELETE | `/auth/mfa` | Disable MFA |
| POST | `/auth/password/forgot` | Request reset |
| POST | `/auth/password/reset` | Reset with token |
| PUT  | `/auth/password/change` | Change password |
| GET  | `/auth/.well-known/jwks.json` | JWKS endpoint |

### Admin (`/admin/*`)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/stats` | System stats |
| GET | `/admin/users` | List users |
| PATCH | `/admin/users/:id/role` | Update role |
| PATCH | `/admin/users/:id/toggle-active` | Enable/disable user |
| GET | `/admin/audit` | Query audit logs |
| GET | `/admin/audit/stream` | SSE audit stream |

## Security Features

- **JWT**: HS256/RS256 with kid header + JWKS endpoint for key rotation
- **Refresh Token Rotation**: Reuse detection invalidates entire token family
- **Passwords**: bcrypt (cost≥12) or Argon2id with per-user salt
- **MFA**: TOTP (RFC 6238) with QR enrollment + AES-encrypted backup codes
- **Lockout**: Exponential backoff, CAPTCHA at attempt 5
- **CSRF**: Double-submit cookie (SameSite=Strict)
- **Rate Limiting**: Redis sliding-window per IP + per user
- **Audit**: Immutable append-only logs + SIEM JSON (ELK/Splunk)
- **Signed Links**: HMAC-SHA256 + TTL + optional IP binding

## Running Tests

```bash
cd backend
npm test
```

## GitHub Collaboration

After receiving this code:

```bash
git init
git add .
git commit -m "feat: auth & backend core (Member A)"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-file-vault.git
git push -u origin main
```

To add collaborators: GitHub repo → Settings → Collaborators → Add people
