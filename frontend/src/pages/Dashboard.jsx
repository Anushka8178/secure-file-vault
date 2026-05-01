/**
 * Dashboard.jsx — Member C
 * User session dashboard: lists all active sessions with device info,
 * allows revoking individual sessions.
 *
 * Security rules:
 * - No innerHTML — all JSX rendering
 * - Sessions fetched via cookie auth (client.js)
 * - No sensitive data stored in state beyond what's displayed
 *
 * Consumes: GET /auth/sessions → [{ id, deviceName, ipAddress, userAgent, createdAt, lastSeenAt, isCurrent }]
 *           DELETE /auth/sessions/:id (via SessionCard)
 */

import { useState, useEffect } from 'react';
import SessionCard from '../components/SessionCard.jsx';
import client from '../api/client.js';

export default function Dashboard() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    client.get('/auth/sessions')
      .then(({ data }) => {
        if (!cancelled) setSessions(data.sessions || []);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load sessions.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  function handleRevoke(sessionId) {
    setSessions((prev) => prev.filter((s) => s.id !== sessionId));
  }

  async function handleRevokeAll() {
    if (!window.confirm('Revoke all other sessions? Only your current session will remain.')) return;
    try {
      await client.delete('/auth/sessions');
      setSessions((prev) => prev.filter((s) => s.isCurrent));
    } catch {
      setError('Failed to revoke all sessions.');
    }
  }

  return (
    <main style={styles.page} aria-labelledby="dashboard-heading">
      <h1 id="dashboard-heading" style={styles.heading}>Active Sessions</h1>
      <p style={styles.sub}>
        These devices are currently signed in to your account. Revoke any sessions you don&apos;t recognise.
      </p>

      {loading && <p style={styles.info}>Loading sessions…</p>}
      {error && <p role="alert" style={styles.error}>{error}</p>}

      {!loading && sessions.length === 0 && (
        <p style={styles.info}>No active sessions found.</p>
      )}

      {sessions.map((session) => (
        <SessionCard key={session.id} session={session} onRevoke={handleRevoke} />
      ))}

      {sessions.filter((s) => !s.isCurrent).length > 1 && (
        <button onClick={handleRevokeAll} style={styles.revokeAllBtn}>
          Revoke All Other Sessions
        </button>
      )}
    </main>
  );
}

const styles = {
  page: { maxWidth: 640, margin: '2rem auto', padding: '0 1rem', fontFamily: 'system-ui, sans-serif' },
  heading: { fontSize: '1.5rem', color: '#1a1a2e', marginBottom: '0.4rem' },
  sub: { fontSize: '0.88rem', color: '#666', marginBottom: '1.5rem' },
  info: { color: '#888', fontSize: '0.9rem' },
  error: { color: '#e74c3c', fontSize: '0.85rem' },
  revokeAllBtn: {
    marginTop: '1rem',
    padding: '8px 20px',
    background: '#c0392b',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    fontWeight: 600,
  },
};