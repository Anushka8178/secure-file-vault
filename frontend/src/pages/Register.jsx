/**
 * Register.jsx — Member C
 * Secure registration page with zxcvbn password strength meter.
 *
 * Security rules:
 * - No localStorage
 * - Password strength scored client-side only (never sent for scoring)
 * - Sanitize email/username before send
 * - Error messages generic (no enumeration)
 *
 * Consumes: POST /auth/register
 */

import { useState, useCallback } from 'react';
import PasswordStrength from '../components/PasswordStrength.jsx';
import client from '../api/client.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

export default function Register() {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    setError('');

    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }

    setSubmitting(true);
    try {
      await client.post('/auth/register', {
        email: sanitizePlainText(email.trim()),
        username: sanitizePlainText(username.trim()),
        password,
      });
      setSuccess(true);
    } catch (err) {
      setError(err.message || 'Registration failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }, [email, username, password, confirm]);

  if (success) {
    return (
      <main style={styles.page}>
        <div style={styles.card}>
          <h1 style={styles.heading}>✓ Account Created</h1>
          <p style={{ color: '#555', textAlign: 'center' }}>
            Check your email to verify your account, then{' '}
            <a href="/login" style={styles.link}>sign in</a>.
          </p>
        </div>
      </main>
    );
  }

  return (
    <main style={styles.page} aria-labelledby="register-heading">
      <div style={styles.card}>
        <h1 id="register-heading" style={styles.heading}>Create Account</h1>

        <form onSubmit={handleSubmit} noValidate aria-label="Registration form">
          <div style={styles.field}>
            <label htmlFor="email" style={styles.label}>Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
              style={styles.input}
              disabled={submitting}
            />
          </div>

          <div style={styles.field}>
            <label htmlFor="username" style={styles.label}>Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              minLength={3}
              maxLength={30}
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
              autoComplete="new-password"
              required
              minLength={12}
              style={styles.input}
              disabled={submitting}
              aria-describedby="password-strength"
            />
            {/* zxcvbn strength meter — pure client-side, no data sent */}
            <div id="password-strength">
              <PasswordStrength password={password} />
            </div>
          </div>

          <div style={styles.field}>
            <label htmlFor="confirm" style={styles.label}>Confirm Password</label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
              style={{
                ...styles.input,
                borderColor:
                  confirm && password !== confirm ? '#e74c3c'
                  : confirm && password === confirm ? '#2ecc71'
                  : undefined,
              }}
              disabled={submitting}
              aria-invalid={confirm !== '' && password !== confirm}
            />
            {confirm && password !== confirm && (
              <p style={styles.fieldError} role="alert">Passwords do not match.</p>
            )}
          </div>

          {error && (
            <p role="alert" aria-live="assertive" style={styles.error}>
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting || password !== confirm || password.length < 12}
            style={styles.button}
          >
            {submitting ? 'Creating account…' : 'Create Account'}
          </button>
        </form>

        <p style={styles.footer}>
          Already have an account?{' '}
          <a href="/login" style={styles.link}>Sign in</a>
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
    maxWidth: 440,
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
  fieldError: { color: '#e74c3c', fontSize: '0.8rem', margin: '2px 0 0 0' },
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