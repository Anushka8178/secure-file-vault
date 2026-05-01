/**
 * Login.jsx — Member C
 * Secure login page.
 *
 * Security rules:
 * - No localStorage — auth cookies set by backend (HttpOnly, Secure, SameSite=Strict)
 * - Credentials sent via POST body over HTTPS only
 * - CSRF token auto-attached by client.js
 * - No sensitive data logged or stored in component state after response
 * - Error messages are generic (no user enumeration)
 *
 * Consumes: POST /auth/login → sets HttpOnly session cookie
 */

import { useState, useCallback } from 'react';
import client from '../api/client.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [requiresMFA, setRequiresMFA] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      const payload = {
        email: sanitizePlainText(email.trim()),
        password, // not sanitized — bcrypt handles raw input; sanitizing could strip valid chars
        ...(requiresMFA ? { mfaToken: mfaToken.trim() } : {}),
      };

      await client.post('/auth/login', payload);

      // On success, backend sets HttpOnly cookie.
      // Redirect to dashboard — never store token in state/localStorage.
      window.location.replace('/dashboard');
    } catch (err) {
      // Generic error — never reveal whether email exists
      if (err.status === 403 && !requiresMFA) {
        // Backend signals MFA required
        setRequiresMFA(true);
        setError('Enter your 6-digit authenticator code.');
      } else if (err.status === 429) {
        setError('Too many attempts. Please wait before trying again.');
      } else {
        setError('Invalid credentials. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  }, [email, password, mfaToken, requiresMFA]);

  return (
    <main style={styles.page} aria-labelledby="login-heading">
      <div style={styles.card}>
        <h1 id="login-heading" style={styles.heading}>Sign In</h1>

        <form onSubmit={handleSubmit} noValidate aria-label="Login form">
          <div style={styles.field}>
            <label htmlFor="email" style={styles.label}>Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
              aria-required="true"
              style={styles.input}
              disabled={submitting}
            />
          </div>

          <div style={styles.field}>
            <label htmlFor="password" style={styles.label}>Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              aria-required="true"
              style={styles.input}
              disabled={submitting}
            />
          </div>

          {/* MFA field — shown only when backend requires it */}
          {requiresMFA && (
            <div style={styles.field}>
              <label htmlFor="mfa-token" style={styles.label}>
                Authenticator Code
              </label>
              <input
                id="mfa-token"
                type="text"
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                value={mfaToken}
                onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, ''))}
                autoComplete="one-time-code"
                aria-label="6-digit MFA code"
                required
                style={{ ...styles.input, letterSpacing: '0.3em', textAlign: 'center' }}
                disabled={submitting}
                autoFocus
              />
            </div>
          )}

          {error && (
            <p role="alert" aria-live="assertive" style={styles.error}>
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            style={styles.button}
          >
            {submitting ? 'Signing in…' : requiresMFA ? 'Verify & Sign In' : 'Sign In'}
          </button>
        </form>

        <p style={styles.footer}>
          Don&apos;t have an account?{' '}
          <a href="/register" style={styles.link}>Register</a>
        </p>
        <p style={styles.footer}>
          <a href="/auth/password/reset-request" style={styles.link}>
            Forgot password?
          </a>
        </p>
      </div>
    </main>
  );
}

const styles = {
  page: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: '#f0f2f5',
    fontFamily: 'system-ui, sans-serif',
  },
  card: {
    width: '100%',
    maxWidth: 420,
    background: '#fff',
    borderRadius: 10,
    padding: '2rem',
    boxShadow: '0 4px 24px rgba(0,0,0,0.09)',
  },
  heading: { fontSize: '1.5rem', color: '#1a1a2e', marginBottom: '1.5rem', textAlign: 'center' },
  field: { marginBottom: '1rem', display: 'flex', flexDirection: 'column', gap: 4 },
  label: { fontSize: '0.85rem', fontWeight: 600, color: '#333' },
  input: {
    padding: '10px 12px',
    border: '1.5px solid #ddd',
    borderRadius: 6,
    fontSize: '0.95rem',
    outline: 'none',
    transition: 'border-color 0.2s',
  },
  error: {
    color: '#e74c3c',
    fontSize: '0.85rem',
    margin: '0 0 10px 0',
    padding: '8px 12px',
    background: '#fdecea',
    borderRadius: 6,
  },
  button: {
    width: '100%',
    padding: '11px',
    background: '#1a1a2e',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    fontSize: '1rem',
    fontWeight: 600,
    cursor: 'pointer',
    marginTop: '0.5rem',
  },
  footer: { fontSize: '0.82rem', color: '#777', textAlign: 'center', marginTop: '1rem' },
  link: { color: '#2980b9', textDecoration: 'none' },
};