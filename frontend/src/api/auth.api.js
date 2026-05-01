/**
 * auth.api.js — Member C
 * Thin wrappers around auth endpoints.
 * All calls go through client.js (cookie auth, CSRF, no localStorage).
 *
 * Member A owns the backend endpoints; this file only CALLS them.
 */
import client from './client.js';

export const authApi = {
  /** POST /auth/login — sets HttpOnly session cookie on success */
  login: (email, password, mfaToken) =>
    client.post('/auth/login', { email, password, ...(mfaToken ? { mfaToken } : {}) }),

  /** POST /auth/register */
  register: (email, username, password) =>
    client.post('/auth/register', { email, username, password }),

  /** GET /auth/me — returns { user } or 401 */
  me: () => client.get('/auth/me'),

  /** POST /auth/logout — clears session cookie server-side */
  logout: () => client.post('/auth/logout'),

  /** GET /auth/sessions — returns [{ id, userAgent, ipAddress, createdAt, lastSeenAt, isCurrent }] */
  getSessions: () => client.get('/auth/sessions'),

  /** DELETE /auth/sessions/:id — revokes a single session */
  revokeSession: (sessionId) => client.delete(`/auth/sessions/${sessionId}`),

  /** DELETE /auth/sessions — revokes all sessions except current */
  revokeAllSessions: () => client.delete('/auth/sessions'),

  /** GET /auth/mfa/setup — returns { qrDataURL, secret, backupCodes } */
  getMfaSetup: () => client.get('/auth/mfa/setup'),

  /** POST /auth/mfa/verify — { token } */
  verifyMfa: (token) => client.post('/auth/mfa/verify', { token }),

  /** POST /auth/password/reset-request — { email } */
  requestPasswordReset: (email) =>
    client.post('/auth/password/reset-request', { email }),

  /** POST /auth/password/reset — { token, newPassword } */
  resetPassword: (token, newPassword) =>
    client.post('/auth/password/reset', { token, newPassword }),
};