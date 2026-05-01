/**
 * FileTable.jsx — Member C
 * Displays uploaded files in a table for admin management.
 *
 * Security rules:
 * - All cell content via JSX textContent — no innerHTML
 * - sanitizePlainText() on all string fields from API
 * - Delete via client.js (CSRF header auto-attached)
 *
 * Props:
 *   files    {Array}  — [{ id, originalName, uploadedBy, size, status, createdAt }]
 *   onDelete {fn}     — callback(fileId) after successful delete
 */

import { useState } from 'react';
import client from '../api/client.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

const STATUS_COLORS = {
  approved:    '#27ae60',
  quarantine:  '#e74c3c',
  pending:     '#e67e22',
  deleted:     '#aaa',
};

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

export default function FileTable({ files, onDelete }) {
  const [deletingId, setDeletingId] = useState(null);
  const [error, setError] = useState('');

  async function handleDelete(fileId, fileName) {
    if (!window.confirm(`Delete "${fileName}"? This cannot be undone.`)) return;
    setDeletingId(fileId);
    setError('');
    try {
      await client.delete(`/api/admin/files/${fileId}`);
      onDelete(fileId);
    } catch (err) {
      setError(err.message || 'Failed to delete file.');
    } finally {
      setDeletingId(null);
    }
  }

  if (files.length === 0) {
    return <p style={{ color: '#888', fontSize: '0.9rem' }}>No files found.</p>;
  }

  return (
    <>
      {error && <p role="alert" style={styles.error}>{error}</p>}
      <div style={styles.wrapper} role="region" aria-label="File management table">
        <table style={styles.table} aria-label="Uploaded files">
          <thead>
            <tr>
              {['File Name', 'Uploaded By', 'Size', 'Status', 'Date', 'Actions'].map((h) => (
                <th key={h} style={styles.th} scope="col">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {files.map((file) => {
              // sanitize every string field before rendering
              const safeName = sanitizePlainText(file.originalName || '');
              const safeUser = sanitizePlainText(file.uploadedBy || '');
              const safeStatus = sanitizePlainText(file.status || 'pending');

              return (
                <tr key={file.id} style={styles.tr}>
                  <td style={styles.td}>
                    <span title={safeName} style={styles.fileName}>
                      {safeName}
                    </span>
                  </td>
                  <td style={styles.td}>{safeUser}</td>
                  <td style={styles.td}>{formatBytes(file.size)}</td>
                  <td style={styles.td}>
                    <span
                      style={{
                        ...styles.statusBadge,
                        color: STATUS_COLORS[safeStatus] || '#888',
                        borderColor: STATUS_COLORS[safeStatus] || '#ddd',
                      }}
                    >
                      {safeStatus}
                    </span>
                  </td>
                  <td style={styles.td}>{formatDate(file.createdAt)}</td>
                  <td style={styles.td}>
                    <button
                      onClick={() => handleDelete(file.id, safeName)}
                      disabled={deletingId === file.id || safeStatus === 'deleted'}
                      aria-label={`Delete file ${safeName}`}
                      style={styles.deleteBtn}
                    >
                      {deletingId === file.id ? 'Deleting…' : 'Delete'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

const styles = {
  wrapper: { overflowX: 'auto', borderRadius: 6, border: '1px solid #e0e0e0' },
  table: { width: '100%', borderCollapse: 'collapse', fontFamily: 'system-ui, sans-serif', fontSize: '0.85rem' },
  th: {
    padding: '10px 12px',
    background: '#f0f2f5',
    textAlign: 'left',
    fontWeight: 600,
    color: '#333',
    borderBottom: '2px solid #ddd',
    whiteSpace: 'nowrap',
  },
  tr: { borderBottom: '1px solid #f0f0f0' },
  td: { padding: '10px 12px', color: '#444', verticalAlign: 'middle' },
  fileName: {
    display: 'inline-block',
    maxWidth: 200,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    verticalAlign: 'bottom',
  },
  statusBadge: {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 12,
    border: '1px solid',
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  },
  deleteBtn: {
    padding: '4px 12px',
    background: '#e74c3c',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    cursor: 'pointer',
    fontSize: '0.8rem',
  },
  error: { color: '#e74c3c', fontSize: '0.85rem', marginBottom: 8 },
};