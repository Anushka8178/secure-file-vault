/**
 * Upload.jsx — Member C
 * Secure file upload page.
 *
 * Security rules:
 * - File size validated client-side before send (≤5 MB; enforced server-side by Member B)
 * - No file content read into JS memory unnecessarily
 * - Upload via useUpload hook → XHR with CSRF header + cookie auth
 * - Filename displayed via JSX textContent — never innerHTML
 * - Scan status polled from /api/files/:id/status
 *
 * Consumes:
 *   POST /upload               (Member B owns endpoint)
 *   GET  /api/files/:id/status (Member B owns endpoint)
 */

import { useState, useRef, useCallback } from 'react';
import { useUpload } from '../hooks/useUpload.js';
import { sanitizePlainText } from '../security/domPurify.config.js';

const MAX_MB = 5;
const MAX_BYTES = MAX_MB * 1024 * 1024;

const ALLOWED_EXTENSIONS = [
  '.pdf', '.png', '.jpg', '.jpeg', '.gif',
  '.txt', '.csv', '.docx', '.xlsx',
];

function getExtension(name = '') {
  const idx = name.lastIndexOf('.');
  return idx >= 0 ? name.slice(idx).toLowerCase() : '';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const STATUS_COLOR = {
  approved:   '#27ae60',
  quarantine: '#e74c3c',
  pending:    '#e67e22',
  scanning:   '#2980b9',
};

export default function Upload() {
  const { upload, progress, uploading, error: uploadError, reset } = useUpload();
  const [file, setFile]                   = useState(null);
  const [validationError, setValidationError] = useState('');
  const [uploadedFile, setUploadedFile]   = useState(null); // { id, name, status }
  const [scanStatus, setScanStatus]       = useState('');
  const inputRef = useRef(null);

  // ── Validation ──────────────────────────────────────────────────────────────
  const validateFile = useCallback((f) => {
    if (!f) return 'No file selected.';
    if (f.size > MAX_BYTES) return `File too large. Maximum ${MAX_MB} MB.`;
    const ext = getExtension(f.name);
    if (!ALLOWED_EXTENSIONS.includes(ext))
      return `File type not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
    return '';
  }, []);

  function handleFileChange(e) {
    const selected = e.target.files?.[0] || null;
    setValidationError('');
    setUploadedFile(null);
    setScanStatus('');
    reset();
    if (!selected) { setFile(null); return; }
    const err = validateFile(selected);
    if (err) {
      setValidationError(err);
      setFile(null);
      e.target.value = '';
      return;
    }
    setFile(selected);
  }

  // ── Drag-and-drop ───────────────────────────────────────────────────────────
  function handleDrop(e) {
    e.preventDefault();
    const dropped = e.dataTransfer.files?.[0] || null;
    if (!dropped) return;
    const err = validateFile(dropped);
    if (err) { setValidationError(err); return; }
    setValidationError('');
    setFile(dropped);
    reset();
  }

  function handleDragOver(e) { e.preventDefault(); }

  // ── Submit ──────────────────────────────────────────────────────────────────
  async function handleSubmit(e) {
    e.preventDefault();
    if (!file) return;

    try {
      const data = await upload(file);
      const uploaded = {
        id:     data.file?.id,
        name:   sanitizePlainText(data.file?.name || file.name),
        status: sanitizePlainText(data.file?.status || 'pending'),
      };
      setUploadedFile(uploaded);
      setFile(null);
      if (inputRef.current) inputRef.current.value = '';
      if (uploaded.id) pollScanStatus(uploaded.id);
    } catch {
      // uploadError already set in useUpload hook
    }
  }

  // ── Poll scan status (Member B's ClamAV pipeline) ───────────────────────────
  function pollScanStatus(fileId) {
    setScanStatus('scanning');
    let attempts = 0;
    const MAX_ATTEMPTS = 20;

    const intervalId = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch(`/api/files/${fileId}/status`, {
          credentials: 'include',
        });
        if (!res.ok) throw new Error('Status fetch failed');
        const data = await res.json();
        const status = sanitizePlainText(data.status || '');
        setScanStatus(status);
        setUploadedFile((prev) => prev ? { ...prev, status } : prev);

        if (status === 'approved' || status === 'quarantine' || attempts >= MAX_ATTEMPTS) {
          clearInterval(intervalId);
        }
      } catch {
        clearInterval(intervalId);
        setScanStatus('unknown');
      }
    }, 2000);
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <main style={styles.page} aria-labelledby="upload-heading">
      <div style={styles.card}>
        <h1 id="upload-heading" style={styles.heading}>Upload File</h1>
        <p style={styles.sub}>
          Max {MAX_MB} MB &nbsp;·&nbsp; Allowed: {ALLOWED_EXTENSIONS.join(', ')}
        </p>

        <form onSubmit={handleSubmit} noValidate>

          {/* Drop zone */}
          <div
            role="button"
            tabIndex={0}
            aria-label="File drop zone. Click or drag a file here."
            style={styles.dropZone}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onClick={() => inputRef.current?.click()}
            onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              accept={ALLOWED_EXTENSIONS.join(',')}
              onChange={handleFileChange}
              aria-label="File input"
              style={{ display: 'none' }}
            />
            {file ? (
              <p style={styles.fileName}>
                📄 {sanitizePlainText(file.name)}{' '}
                <span style={styles.fileSize}>({formatBytes(file.size)})</span>
              </p>
            ) : (
              <p style={styles.dropText}>
                Drag &amp; drop a file here, or <u>click to browse</u>
              </p>
            )}
          </div>

          {/* Validation error */}
          {validationError && (
            <p role="alert" style={styles.error}>{validationError}</p>
          )}

          {/* Upload error from hook */}
          {uploadError && (
            <p role="alert" style={styles.error}>{uploadError}</p>
          )}

          {/* Progress bar */}
          {uploading && (
            <div
              role="progressbar"
              aria-valuenow={progress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Uploading: ${progress}%`}
              style={styles.progressWrap}
            >
              <div style={{ ...styles.progressBar, width: `${progress}%` }} />
              <span style={styles.progressLabel}>{progress}%</span>
            </div>
          )}

          <button
            type="submit"
            disabled={!file || uploading}
            style={{
              ...styles.button,
              opacity: !file || uploading ? 0.6 : 1,
              cursor: !file || uploading ? 'not-allowed' : 'pointer',
            }}
          >
            {uploading ? `Uploading… ${progress}%` : 'Upload'}
          </button>
        </form>

        {/* Upload result + scan status */}
        {uploadedFile && (
          <div
            style={styles.result}
            role="status"
            aria-live="polite"
            aria-label={`Upload result for ${uploadedFile.name}`}
          >
            <p style={styles.resultName}>✓ {uploadedFile.name}</p>
            <p style={styles.resultStatus}>
              Scan status:{' '}
              <strong style={{ color: STATUS_COLOR[scanStatus] || '#888' }}>
                {scanStatus || uploadedFile.status}
              </strong>
            </p>
            {scanStatus === 'quarantine' && (
              <p role="alert" style={styles.quarantineWarn}>
                ⚠ File flagged and quarantined. Contact your administrator.
              </p>
            )}
            {scanStatus === 'approved' && (
              <p style={{ color: '#27ae60', fontSize: '0.85rem' }}>
                File passed security scan and is ready.
              </p>
            )}
          </div>
        )}
      </div>
    </main>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const styles = {
  page: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: '#f0f2f5',
    fontFamily: 'system-ui, sans-serif',
    padding: '2rem 1rem',
  },
  card: {
    width: '100%',
    maxWidth: 500,
    background: '#fff',
    borderRadius: 10,
    padding: '2rem',
    boxShadow: '0 4px 24px rgba(0,0,0,0.09)',
  },
  heading: { fontSize: '1.5rem', color: '#1a1a2e', marginBottom: '0.3rem' },
  sub: { fontSize: '0.82rem', color: '#888', marginBottom: '1.5rem' },
  dropZone: {
    border: '2px dashed #bbb',
    borderRadius: 8,
    padding: '2rem',
    textAlign: 'center',
    cursor: 'pointer',
    marginBottom: '1rem',
    transition: 'border-color 0.2s',
    background: '#fafafa',
  },
  dropText: { color: '#888', fontSize: '0.9rem', margin: 0 },
  fileName: { color: '#1a1a2e', fontWeight: 600, margin: 0 },
  fileSize: { color: '#888', fontWeight: 400, fontSize: '0.85rem' },
  error: {
    color: '#e74c3c',
    fontSize: '0.85rem',
    margin: '0 0 10px 0',
    padding: '8px 12px',
    background: '#fdecea',
    borderRadius: 6,
  },
  progressWrap: {
    position: 'relative',
    height: 22,
    background: '#eee',
    borderRadius: 11,
    overflow: 'hidden',
    marginBottom: '1rem',
  },
  progressBar: {
    height: '100%',
    background: '#2ecc71',
    borderRadius: 11,
    transition: 'width 0.3s ease',
  },
  progressLabel: {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    fontSize: '0.75rem',
    fontWeight: 700,
    color: '#333',
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
    transition: 'opacity 0.2s',
  },
  result: {
    marginTop: '1.5rem',
    padding: '14px 16px',
    border: '1px solid #e0e0e0',
    borderRadius: 8,
    background: '#f9fff9',
  },
  resultName: { fontWeight: 700, color: '#1a1a2e', margin: '0 0 6px 0' },
  resultStatus: { fontSize: '0.88rem', color: '#555', margin: '0 0 4px 0' },
  quarantineWarn: {
    color: '#e74c3c',
    fontSize: '0.85rem',
    margin: '6px 0 0 0',
    fontWeight: 600,
  },
};