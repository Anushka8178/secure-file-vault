/**
 * SecureLink.jsx — Member C
 * Displays a generated expiring download link with:
 *   - Copyable URL (textContent, no innerHTML)
 *   - QR code rendered as <img src={dataURL}>
 *   - Revoke button
 *   - Countdown to expiry
 *
 * Security rules:
 * - Link URL rendered via textContent / value attribute — never innerHTML
 * - QR dataURL from backend set as <img src> — safe, no DOM injection
 * - Revoke calls DELETE /api/links/:linkId
 *
 * Props:
 *   link {object} — { id, url, qrDataURL, expiresAt, label }
 *   onRevoke {fn} — callback(linkId)
 */

import { useState, useEffect } from 'react';
import client from '../api/client.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

function useCountdown(expiresAt) {
  const [secondsLeft, setSecondsLeft] = useState(() =>
    Math.max(0, Math.floor((new Date(expiresAt) - Date.now()) / 1000))
  );

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const id = setInterval(() => {
      setSecondsLeft((s) => Math.max(0, s - 1));
    }, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return secondsLeft;
}

function formatCountdown(seconds) {
  if (seconds <= 0) return 'Expired';
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

export default function SecureLink({ link, onRevoke }) {
  const [revoking, setRevoking] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const secondsLeft = useCountdown(link.expiresAt);
  const isExpired = secondsLeft <= 0;

  // Sanitize label — textContent only
  const safeLabel = sanitizePlainText(link.label || 'Secure Link');
  const safeUrl = sanitizePlainText(link.url || '');

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(safeUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError('Copy failed. Please copy the URL manually.');
    }
  }

  async function handleRevoke() {
    if (!window.confirm('Revoke this link? It will immediately stop working.')) return;
    setRevoking(true);
    setError('');
    try {
      await client.delete(`/api/links/${link.id}`);
      onRevoke(link.id);
    } catch (err) {
      setError(err.message || 'Failed to revoke link.');
    } finally {
      setRevoking(false);
    }
  }

  return (
    <article
      style={{
        ...styles.card,
        opacity: isExpired ? 0.6 : 1,
        borderColor: isExpired ? '#ddd' : '#2980b9',
      }}
      aria-label={`Secure link: ${safeLabel}`}
    >
      <div style={styles.topRow}>
        <div style={{ flex: 1 }}>
          <p style={styles.label}>{safeLabel}</p>

          {/* URL — read-only input allows selection without innerHTML */}
          <input
            type="text"
            readOnly
            value={safeUrl}
            aria-label="Secure link URL"
            style={styles.urlInput}
            onFocus={(e) => e.target.select()}
          />

          <div style={styles.metaRow}>
            <span
              style={{
                ...styles.timer,
                color: isExpired ? '#e74c3c' : secondsLeft < 60 ? '#e67e22' : '#27ae60',
              }}
              aria-label={`Link expires in ${formatCountdown(secondsLeft)}`}
            >
              ⏱ {formatCountdown(secondsLeft)}
            </span>
            <button
              onClick={handleCopy}
              disabled={isExpired}
              aria-label="Copy link to clipboard"
              style={styles.copyBtn}
            >
              {copied ? '✓ Copied' : 'Copy'}
            </button>
            <button
              onClick={handleRevoke}
              disabled={revoking || isExpired}
              aria-label="Revoke this link"
              style={styles.revokeBtn}
            >
              {revoking ? 'Revoking…' : 'Revoke'}
            </button>
          </div>
        </div>

        {/* QR Code — rendered as <img src={dataURL}>, never innerHTML */}
        {link.qrDataURL && !isExpired && (
          <img
            src={link.qrDataURL}
            alt="QR code for secure link"
            width={90}
            height={90}
            style={styles.qr}
          />
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
    padding: '14px 16px',
    marginBottom: 12,
    background: '#fafcff',
    fontFamily: 'system-ui, sans-serif',
    transition: 'opacity 0.3s',
  },
  topRow: { display: 'flex', gap: 12, alignItems: 'flex-start' },
  label: { fontWeight: 700, margin: '0 0 6px 0', color: '#1a1a2e', fontSize: '0.95rem' },
  urlInput: {
    width: '100%',
    padding: '6px 10px',
    border: '1px solid #ccc',
    borderRadius: 4,
    fontSize: '0.8rem',
    fontFamily: 'monospace',
    color: '#333',
    background: '#f5f8ff',
    boxSizing: 'border-box',
    cursor: 'text',
  },
  metaRow: { display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, flexWrap: 'wrap' },
  timer: { fontSize: '0.82rem', fontWeight: 600 },
  copyBtn: {
    padding: '4px 12px',
    background: '#2980b9',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    cursor: 'pointer',
    fontSize: '0.8rem',
  },
  revokeBtn: {
    padding: '4px 12px',
    background: '#e74c3c',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    cursor: 'pointer',
    fontSize: '0.8rem',
  },
  qr: { borderRadius: 4, border: '1px solid #ddd', flexShrink: 0 },
  error: { color: '#e74c3c', fontSize: '0.8rem', margin: '6px 0 0 0' },
};