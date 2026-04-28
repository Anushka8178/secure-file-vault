# API Documentation

## Base URL
`https://your-domain.com/api` (or `http://localhost:5000` in dev)

## Authentication
All protected routes require:
```
Authorization: Bearer <access_token>
```

## Auth Endpoints

### POST /auth/register
```json
{ "email": "user@example.com", "username": "johndoe", "password": "MyP@ss1!" }
```
Response `201`: `{ user: { id, email, username, role } }`

### POST /auth/login
```json
{ "email": "user@example.com", "password": "MyP@ss1!", "totpCode": "123456" }
```
Response `200`: `{ accessToken, user }` | `{ mfaRequired: true }` if MFA pending

### POST /auth/refresh
Cookie: `refresh_token=<token>` (set automatically)
Response `200`: `{ accessToken }`

### GET /.well-known/jwks.json
Public JWKS for RS256 key verification

## Error Format
```json
{ "ok": false, "code": "AUTH_FAILED", "message": "Authentication failed" }
```

## Common Error Codes
| Code | Status | Meaning |
|------|--------|---------|
| `AUTH_FAILED` | 401 | Invalid credentials |
| `TOKEN_EXPIRED` | 401 | Access token expired |
| `ACCOUNT_LOCKED` | 401 | Too many failed attempts |
| `MFA_INVALID` | 401 | Wrong TOTP code |
| `FORBIDDEN` | 403 | Insufficient role |
| `CSRF_INVALID` | 403 | CSRF mismatch |
| `RATE_LIMITED` | 429 | Too many requests |
| `VALIDATION_ERROR` | 422 | Input validation failed |
