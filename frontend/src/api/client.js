/**
 * client.js — Member C Security
 * Secure Axios base client.
 *
 * Security rules enforced here:
 *   1. credentials: 'include' — cookies sent automatically (HttpOnly, Secure, SameSite=Strict)
 *   2. CSRF token read from cookie (not localStorage) and sent as X-CSRF-Token header
 *   3. NO tokens stored in localStorage or sessionStorage
 *   4. All responses checked for 401 (token expired) → redirect to /login
 *   5. No sensitive data logged
 *
 * Backend team (Member A) owns the /auth endpoints and CSRF cookie generation.
 * This file only CONSUMES those APIs — it does not define them.
 */

import axios from 'axios';

// ── Constants ─────────────────────────────────────────────────────────────────
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';
const CSRF_COOKIE_NAME = 'csrf_token';       // set by backend (NOT HttpOnly — must be readable)
const CSRF_HEADER_NAME = 'X-CSRF-Token';     // double-submit cookie pattern (Member A)

// ── CSRF Helper ───────────────────────────────────────────────────────────────
/**
 * Reads the CSRF token from the csrf_token cookie.
 * This cookie is set by the backend as a plain (non-HttpOnly) cookie
 * so the frontend can read and echo it back in the header.
 *
 * The session/auth cookies are HttpOnly — unreadable by JS, sent automatically.
 *
 * @returns {string} CSRF token or empty string
 */
function getCSRFToken() {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === CSRF_COOKIE_NAME) {
      return decodeURIComponent(value);
    }
  }
  return '';
}

// ── Axios Instance ────────────────────────────────────────────────────────────
const client = axios.create({
  baseURL: API_BASE_URL,

  // Send cookies (session, auth) with every request — required for HttpOnly cookies
  withCredentials: true,

  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },

  // Timeout — prevent hanging requests
  timeout: 15000,
});

// ── Request Interceptor ───────────────────────────────────────────────────────
client.interceptors.request.use(
  (config) => {
    // Attach CSRF token for all state-changing methods
    const method = (config.method || '').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        config.headers[CSRF_HEADER_NAME] = csrfToken;
      }
      // If no CSRF token found, still send the request —
      // the backend will reject it with 403 if required.
    }

    // SECURITY: Never add Authorization header with a Bearer token.
    // Auth is handled exclusively via HttpOnly cookies.
    // If any code tries to set Authorization here, strip it.
    if (config.headers['Authorization']) {
      delete config.headers['Authorization'];
      console.warn(
        '[client] Authorization header stripped — use cookie-based auth only.'
      );
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response Interceptor ──────────────────────────────────────────────────────
client.interceptors.response.use(
  (response) => response,

  (error) => {
    if (!error.response) {
      // Network error or timeout
      return Promise.reject({
        message: 'Network error. Please check your connection.',
        status: null,
      });
    }

    const { status } = error.response;

    // 401 — session expired or not authenticated
    if (status === 401) {
      // Clear any non-HttpOnly state (nothing in localStorage — there is none)
      // Redirect to login; React Router will handle it
      window.location.replace('/login');
      return Promise.reject({ message: 'Session expired.', status: 401 });
    }

    // 403 — CSRF failure or insufficient permissions
    if (status === 403) {
      console.error('[client] 403 Forbidden — possible CSRF failure or insufficient role.');
    }

    // 429 — rate limited (Member A's Redis limiter)
    if (status === 429) {
      console.warn('[client] 429 Too Many Requests — rate limit hit.');
    }

    // Never log full error response body (may contain sensitive data)
    return Promise.reject({
      message: error.response.data?.message || 'An error occurred.',
      status,
    });
  }
);

export default client;