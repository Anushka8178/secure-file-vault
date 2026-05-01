/**
 * LinkGenerator.jsx — Member C
 * Admin page: generate expiring HMAC-signed download links (Member A creates them).
 * Displays generated links with QR codes and revoke capability via SecureLink component.
 *
 * Security rules:
 * - File IDs from a <select> — no free-text URL construction by user
 * - All rendered text via JSX (no innerHTML)
 * - POST /api/links body sanitized before send
 *
 * Consumes:
 *   GET  /api/files          → [{ id, name }]
 *   POST /api/links          → { id, url, qrDataURL, expiresAt, label }
 *   DELETE /api/links/:id    (via SecureLink component)
 */

import { useState, useEffect } from 'react';
import SecureLink from '../components/SecureLink.jsx';
import client from '../api/client.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

const TTL_OPTIONS = [
  { label: '15 minutes', value: 900 },
  { label: '1 hour',     value: 3600 },
  { label: '24 hours',   value: 86400 },
];

export default function LinkGenerator() {
  const [files, setFiles] = useState([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [ttl, setTtl] = useState(900);
  const [bindIP, setBindIP] = useState(false);
  const [links, setLinks] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');
  const [loadingFiles, setLoadingFiles] = useState(true);

  // Fetch available files
  useEffect(() => {
    client.get('/api/files')
      .then(({ data }) => {
        setFiles(data.files || []);
        if (data.files?.length) setSelectedFileId(data.files[0].id);
      })
      .catch(() => setError('Failed to load files.'))
      .finally(() => setLoadingFiles(false));
  }, []);

  async function handleGenerate(e) {
    e.preventDefault();
    if (!selectedFileId) return;
    setGenerating(true);
    setError('');

    try {
      const { data } = await client.post('/api/links', {
        fileId: sanitizePlainText(selectedFileId),
        ttl,
        bindIP,
      });
      setLinks((prev) => [data, ...prev]);
    } catch (err) {
      setError(err.message || 'Failed to generate link.');
    } finally {
      setGenerating(false);
    }
  }

  function handleRevoke(linkId) {
    setLinks((prev) => prev.filter((l) => l.id !== linkId));
  }

  return (
    <main style={styles.page} aria-labelledby="linksgen-heading">
      <h1 id="linksgen-heading" style={styles.heading}>
        Expiring Link Generator
      </h1>
      <p style={styles.sub}>
        Generate HMAC-signed, time-limited download links. Links can optionally be bound to your current IP.
      </p>

      {/* Generator form */}
      <form onSubmit={handleGenerate} style={styles.form} noValidate>
        <div style={styles.field}>
          <label htmlFor="file-select" style={styles.label}>File</label>
          {loadingFiles ? (
            <p style={styles.info}>Loading files…</p>
          ) : (
            <select
              id="file-select"
              value={selectedFileId}
              onChange={(e) => setSelectedFileId(e.target.value)}
              style={styles.select}
              required
              aria-label="Select file to share"
            >
              {files.map((f) => (
                <option key={f.id} value={f.id}>
                  {/* textContent via JSX — safe */}
                  {sanitizePlainText(f.name)}
                </option>
              ))}
            </select>
          )}
        </div>

        <div style={styles.field}>
          <label htmlFor="ttl-select" style={styles.label}>Expiry</label>
          <select
            id="ttl-select"
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
            style={styles.select}
            aria-label="Link expiry duration"
          >
            {TTL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div style={styles.checkRow}>
          <input
            type="checkbox"
            id="bind-ip"
            checked={bindIP}
            onChange={(e) => setBindIP(e.target.checked)}
          />
          <label htmlFor="bind-ip" style={styles.checkLabel}>
            Bind link to my current IP address
          </label>
        </div>

        {error && <p role="alert" style={styles.error}>{error}</p>}

        <button
          type="submit"
          disabled={generating || !selectedFileId || loadingFiles}
          style={styles.genBtn}
        >
          {generating ? 'Generating…' : 'Generate Link'}
        </button>
      </form>

      {/* Generated links */}
      {links.length > 0 && (
        <section aria-labelledby="links-heading" style={{ marginTop: '2rem' }}>
          <h2 id="links-heading" style={styles.subheading}>
            Generated Links
          </h2>
          {links.map((link) => (
            <SecureLink key={link.id} link={link} onRevoke={handleRevoke} />
          ))}
        </section>
      )}
    </main>
  );
}

const styles = {
  page: { maxWidth: 680, margin: '2rem auto', padding: '0 1rem', fontFamily: 'system-ui, sans-serif' },
  heading: { fontSize: '1.5rem', color: '#1a1a2e', marginBottom: '0.4rem' },
  subheading: { fontSize: '1.1rem', color: '#1a1a2e', marginBottom: '0.8rem' },
  sub: { fontSize: '0.88rem', color: '#666', marginBottom: '1.5rem' },
  form: {
    background: '#f8f9fc',
    border: '1px solid #e0e4ed',
    borderRadius: 8,
    padding: '1.5rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  field: { display: 'flex', flexDirection: 'column', gap: 4 },
  label: { fontSize: '0.85rem', fontWeight: 600, color: '#333' },
  select: {
    padding: '8px 10px',
    border: '1px solid #ccc',
    borderRadius: 6,
    fontSize: '0.9rem',
    background: '#fff',
  },
  checkRow: { display: 'flex', alignItems: 'center', gap: 8 },
  checkLabel: { fontSize: '0.88rem', color: '#444', cursor: 'pointer' },
  genBtn: {
    padding: '10px',
    background: '#1a1a2e',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    fontSize: '0.95rem',
    cursor: 'pointer',
    fontWeight: 600,
  },
  info: { color: '#888', fontSize: '0.88rem', margin: 0 },
  error: { color: '#e74c3c', fontSize: '0.85rem', margin: 0 },
};