/**
 * useAuditStream.js — Member C
 * React hook for consuming the audit log SSE stream.
 *
 * Security rules:
 * - EventSource sends cookies automatically (same-origin, withCredentials)
 * - No auth token in query string or URL
 * - All parsed data sanitized via sanitizePlainText before storing in state
 *
 * Consumes: GET /api/audit/stream (SSE)
 *
 * Returns: { entries, connected, error }
 */

import { useState, useEffect } from 'react';
import { sanitizePlainText } from '../security/domPurify.config.js';

const MAX_ENTRIES = 200;

export function useAuditStream() {
  const [entries, setEntries] = useState([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const es = new EventSource('/api/audit/stream', { withCredentials: true });

    es.onopen = () => {
      setConnected(true);
      setError('');
    };

    es.onmessage = (event) => {
      let parsed;
      try {
        parsed = JSON.parse(event.data);
      } catch {
        return;
      }

      const entry = {
        id:        Date.now() + Math.random(),
        timestamp: sanitizePlainText(parsed.timestamp || ''),
        action:    sanitizePlainText(parsed.action || ''),
        actor:     sanitizePlainText(parsed.actor || ''),
        ip:        sanitizePlainText(parsed.ip || ''),
        level:     sanitizePlainText(parsed.level || 'INFO'),
        details:   sanitizePlainText(parsed.details || ''),
      };

      setEntries((prev) => {
        const next = [...prev, entry];
        return next.length > MAX_ENTRIES ? next.slice(-MAX_ENTRIES) : next;
      });
    };

    es.onerror = () => {
      setConnected(false);
      setError('Stream disconnected. Reconnecting…');
    };

    return () => es.close();
  }, []);

  return { entries, connected, error };
}