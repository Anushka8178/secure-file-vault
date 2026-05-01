/**
 * SessionCard.jsx — Member C
 * Displays a single active session with device info and revoke button.
 *
 * Security rules:
 * - All text rendered via JSX (no innerHTML)
 * - Revoke calls DELETE /auth/sessions/:sessionId via client.js (cookie auth, CSRF header)
 * - No sensitive token data displayed or stored
 *
 * Props:
 *   session {object}   — { id, deviceName, ipAddress, userAgent, createdAt, lastSeenAt, isCurrent }
 *   onRevoke {fn}      — callback(sessionId) after successful revoke
 */

import { useState } from 'react';
import client from '../api/client.js';

function parseUA(ua = '') {
  // Simple UA parser — no library needed, display only
  if (!ua) return 'Unknown device';
  if (/iPhone|iPad|iPod/i.test(ua)) return '📱 iOS Device';
  if (/Android/i.test(ua)) return '📱 Android Device';
  if (/Windows/i.test(ua)) return '💻 Windows';
  if (/Mac OS X/i.test(ua)) return '💻 macOS';
  if (/Linux/i.test(ua)) return '🖥 Linux';
  return '🌐 Unknown Device';
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

export default function SessionCard({ session, onRevoke }) {
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState('');

  async function handleRevoke() {
    if (!window.confirm('Revoke this session? The device will be logged out.')) return;
    setRevoking(true);
    setError('');
    try {
      await client.delete(`/auth/sessions/${session.id}`);
      onRevoke(session.id);
    } catch (err) {
      setError(err.message || 'Failed to revoke session.');
    } finally {
      setRevoking(false);
    }
  }

  return (
    <article
      style={{
        ...styles.card,
        borderColor: session.isCurrent ? '#2ecc71' : '#e0e0e0',
        background: session.isCurrent ? '#f0fdf4' : '#fafafa',
      }}
      aria-label={`Session: ${parseUA(session.userAgent)}`}
    >
      <div style={styles.row}>
        <div>
          <p style={styles.device}>
            {parseUA(session.userAgent)}
            {session.isCurrent && (
              <span style={styles.currentBadge}>Current</span>
            )}
          </p>
          <p style={styles.meta}>
            IP: <strong>{session.ipAddress || '—'}</strong>
          </p>
          <p style={styles.meta}>
            Signed in: <strong>{formatDate(session.createdAt)}</strong>
          </p>
          <p style={styles.meta}>
            Last active: <strong>{formatDate(session.lastSeenAt)}</strong>
          </p>
        </div>

        {/* Don't show revoke on current session — user must logout properly */}
        {!session.isCurrent && (
          <button
            onClick={handleRevoke}
            disabled={revoking}
            aria-label={`Revoke session from ${parseUA(session.userAgent)}`}
            style={styles.revokeBtn}
          >
            {revoking ? 'Revoking…' : 'Revoke'}
          </button>
        )}
      </div>

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}
    </article>
  );
}

const styles = {
  card: {
    border: '1.5px solid',
    borderRadius: 8,
    padding: '14px 18px',
    marginBottom: 12,
    fontFamily: 'system-ui, sans-serif',
  },
  row: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: 12,
  },
  device: { fontWeight: 700, margin: '0 0 4px 0', color: '#1a1a2e', display: 'flex', gap: 8, alignItems: 'center' },
  currentBadge: {
    fontSize: '0.7rem',
    background: '#2ecc71',
    color: '#fff',
    borderRadius: 4,
    padding: '1px 6px',
    fontWeight: 600,
    letterSpacing: '0.05em',
  },
  meta: { margin: '2px 0', fontSize: '0.82rem', color: '#555' },
  revokeBtn: {
    flexShrink: 0,
    padding: '6px 14px',
    background: '#e74c3c',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    fontSize: '0.85rem',
    fontWeight: 600,
  },
  error: { color: '#e74c3c', fontSize: '0.82rem', margin: '6px 0 0 0' },
};