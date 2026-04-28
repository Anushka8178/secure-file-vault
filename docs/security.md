# Security Design

## Authentication Flow
1. User submits email + password (+ optional TOTP)
2. Account lockout checked (exponential backoff, CAPTCHA at attempt 5)
3. Password verified via bcrypt (cost≥12) or Argon2id
4. If MFA enabled: TOTP code or backup code verified
5. Access token (15m JWT) + Refresh token (7d, HttpOnly cookie) issued
6. Audit log written

## Refresh Token Rotation (RTR)
- Each refresh produces a new token in the same "family"
- Old token marked `used=true` immediately
- If a used token is presented → entire family invalidated (reuse attack detected)
- Audit event fired on compromise

## Password Security
- bcrypt with cost≥12 (configurable; minimum enforced)
- Optional Argon2id (64MB mem, 3 iterations, 4 parallelism)
- Per-user salt (inherent in both algorithms)
- HMAC-SHA256 reset tokens with 15-minute TTL

## MFA (TOTP RFC 6238)
- 32-byte random secret per user
- QR code enrollment via `otpauth://` URI
- ±1 period drift tolerance
- 10 backup codes per user, AES-256-GCM encrypted at rest
- Backup code consumed on use, cannot be reused

## CSRF Protection
- Double-submit cookie pattern
- Cookie: `csrf_token` (SameSite=Strict, not HttpOnly)
- Header: `x-csrf-token` (must match cookie via timingSafeEqual)
- Skips safe methods (GET, HEAD, OPTIONS)

## Rate Limiting (Redis Sliding Window)
- Global: 100 req/min per IP
- Auth endpoints: 10 req/min per IP
- Per-user: 200 req/min

## Audit Log
- Append-only MongoDB collection (update/delete middleware blocked)
- JSON structured logs piped to SIEM (ELK/Splunk compatible)
- SSE stream for real-time admin monitoring

## Signed Download Links
- HMAC-SHA256 over `fileId:expires[:ip]`
- Configurable TTL (default 1 hour)
- Optional IP binding
- timingSafeEqual comparison
