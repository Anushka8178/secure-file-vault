/**
 * AuditLogStream.jsx — Member C
 * Renders real-time audit log entries via Server-Sent Events (SSE).
 *
 * Security rules:
 * - EventSource connects to /api/audit/stream (cookie auth, nginx proxies)
 * - All event data rendered via JSX textContent — no innerHTML, no eval
 * - sanitizePlainText() applied to every field from the stream
 * - No sensitive data stored beyond the visible log buffer (maxEntries)
 *
 * Consumes: GET /api/audit/stream (SSE, Member A exposes this endpoint)
 */

import { useEffect, useRef, useState } from 'react';
import { sanitizePlainText } from '../security/domPurify.config.js';

const MAX_ENTRIES = 200; // keep last 200 log entries in memory

function levelColor(level = '') {
  switch (level.toUpperCase()) {
    case 'ERROR':   return '#e74c3c';
    case 'WARN':    return '#e67e22';
    case 'INFO':    return '#2980b9';
    case 'SUCCESS': return '#27ae60';
    default:        return '#888';
  }
}

export default function AuditLogStream() {
  const [entries, setEntries] = useState([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');
  const bottomRef = useRef(null);
  const esRef = useRef(null);

  useEffect(() => {
    // SSE — browser sends cookies automatically with EventSource (same-origin)
    const es = new EventSource('/api/audit/stream', { withCredentials: true });
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setError('');
    };

    es.onmessage = (event) => {
      let parsed;
      try {
        parsed = JSON.parse(event.data);
      } catch {
        return; // ignore malformed events
      }

      // Sanitize every string field — no innerHTML ever touches these
      const entry = {
        id: Date.now() + Math.random(),
        timestamp:  sanitizePlainText(parsed.timestamp || ''),
        action:     sanitizePlainText(parsed.action || ''),
        actor:      sanitizePlainText(parsed.actor || ''),
        ip:         sanitizePlainText(parsed.ip || ''),
        level:      sanitizePlainText(parsed.level || 'INFO'),
        details:    sanitizePlainText(parsed.details || ''),
      };

      setEntries((prev) => {
        const next = [...prev, entry];
        return next.length > MAX_ENTRIES ? next.slice(-MAX_ENTRIES) : next;
      });
    };

    es.onerror = () => {
      setConnected(false);
      setError('Stream disconnected. Reconnecting…');
      // EventSource retries automatically
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);

  // Auto-scroll to bottom on new entries
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [entries]);

  return (
    <section aria-labelledby="audit-heading" style={styles.section}>
      <div style={styles.header}>
        <h2 id="audit-heading" style={styles.heading}>
          Live Audit Log
        </h2>
        <span
          role="status"
          aria-label={connected ? 'Stream connected' : 'Stream disconnected'}
          style={{ ...styles.dot, background: connected ? '#2ecc71' : '#e74c3c' }}
          title={connected ? 'Connected' : 'Disconnected'}
        />
      </div>

      {error && (
        <p role="alert" style={styles.error}>
          {error}
        </p>
      )}

      <div
        role="log"
        aria-live="polite"
        aria-label="Audit log entries"
        style={styles.log}
      >
        {entries.length === 0 && (
          <p style={styles.empty}>Waiting for events…</p>
        )}
        {entries.map((entry) => (
          <div key={entry.id} style={styles.entry}>
            <span style={styles.ts}>{entry.timestamp}</span>
            <span
              style={{ ...styles.level, color: levelColor(entry.level) }}
              aria-label={`Level: ${entry.level}`}
            >
              {entry.level}
            </span>
            <span style={styles.actor}>{entry.actor}</span>
            <span style={styles.action}>{entry.action}</span>
            {entry.ip && <span style={styles.ip}>({entry.ip})</span>}
            {entry.details && (
              <span style={styles.details}>{entry.details}</span>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </section>
  );
}

const styles = {
  section: { fontFamily: 'monospace', marginTop: '1.5rem' },
  header: { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 },
  heading: { fontSize: '1.1rem', margin: 0, color: '#1a1a2e', fontFamily: 'system-ui, sans-serif' },
  dot: { width: 10, height: 10, borderRadius: '50%', display: 'inline-block' },
  log: {
    background: '#0d1117',
    color: '#c9d1d9',
    borderRadius: 6,
    padding: '12px',
    height: 320,
    overflowY: 'auto',
    fontSize: '0.78rem',
    lineHeight: 1.6,
  },
  entry: { display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: 4 },
  ts: { color: '#6e7681' },
  level: { fontWeight: 700, minWidth: 56 },
  actor: { color: '#79c0ff' },
  action: { color: '#e3b341' },
  ip: { color: '#8b949e' },
  details: { color: '#a8d8a8' },
  empty: { color: '#555', fontStyle: 'italic' },
  error: { color: '#e74c3c', fontSize: '0.82rem', margin: '4px 0' },
};