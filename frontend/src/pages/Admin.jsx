/**
 * Admin.jsx — Member C
 * Admin panel: file management table + live audit log stream.
 *
 * Security rules:
 * - All file/user data rendered via JSX textContent — no innerHTML
 * - File operations via client.js (cookie auth + CSRF header)
 * - AuditLogStream uses SSE with credentials (no token in URL)
 * - Admin route must be protected by PrivateRoute + role check (App.jsx)
 *
 * Consumes:
 *   GET    /api/admin/files        → [{ id, originalName, uploadedBy, size, status, createdAt }]
 *   DELETE /api/admin/files/:id    → 204
 *   GET    /api/audit/stream       (SSE — consumed by AuditLogStream)
 */

import { useState, useEffect } from 'react';
import AuditLogStream from '../components/AuditLogStream.jsx';
import FileTable from '../components/FileTable.jsx';
import client from '../api/client.js';

export default function Admin() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    client.get('/api/admin/files')
      .then(({ data }) => {
        if (!cancelled) setFiles(data.files || []);
      })
      .catch(() => {
        if (!cancelled) setError('Failed to load files.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  function handleDelete(fileId) {
    setFiles((prev) => prev.filter((f) => f.id !== fileId));
  }

  return (
    <main style={styles.page} aria-labelledby="admin-heading">
      <h1 id="admin-heading" style={styles.heading}>
        Admin Panel
      </h1>

      {/* File Management */}
      <section aria-labelledby="files-heading" style={styles.section}>
        <h2 id="files-heading" style={styles.subheading}>
          File Management
        </h2>
        {loading && <p style={styles.info}>Loading files…</p>}
        {error && <p role="alert" style={styles.error}>{error}</p>}
        {!loading && (
          <FileTable files={files} onDelete={handleDelete} />
        )}
      </section>

      {/* Live Audit Log */}
      <section aria-labelledby="audit-section-heading" style={styles.section}>
        <h2 id="audit-section-heading" style={styles.subheading}>
          Live Audit Log
        </h2>
        <AuditLogStream />
      </section>
    </main>
  );
}

const styles = {
  page: { maxWidth: 900, margin: '2rem auto', padding: '0 1rem', fontFamily: 'system-ui, sans-serif' },
  heading: { fontSize: '1.6rem', color: '#1a1a2e', marginBottom: '0.2rem' },
  subheading: { fontSize: '1.1rem', color: '#333', marginBottom: '0.8rem' },
  section: { marginBottom: '2.5rem' },
  info: { color: '#888', fontSize: '0.9rem' },
  error: { color: '#e74c3c', fontSize: '0.85rem' },
};