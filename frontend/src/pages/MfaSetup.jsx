/**
 * MfaSetup.jsx — Member C
 * MFA enrollment UI: QR code display + TOTP countdown timer + backup codes.
 *
 * Security rules:
 * - QR code rendered as <img src={dataURL}> — no innerHTML
 * - TOTP secret displayed via textContent only
 * - Backup codes rendered via JSX map — no dangerouslySetInnerHTML
 * - No localStorage — backup codes shown once then discarded from state
 *
 * Consumes: GET /auth/mfa/setup  → { qrDataURL, secret, backupCodes }
 *           POST /auth/mfa/verify → { token }
 */

import { useState, useEffect, useCallback } from 'react';
import client from '../api/client.js';

const TOTP_PERIOD = 30; // seconds per RFC 6238

function TOTPCountdown() {
  const [secondsLeft, setSecondsLeft] = useState(
    TOTP_PERIOD - (Math.floor(Date.now() / 1000) % TOTP_PERIOD)
  );

  useEffect(() => {
    const tick = () => {
      setSecondsLeft(TOTP_PERIOD - (Math.floor(Date.now() / 1000) % TOTP_PERIOD));
    };
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, []);

  const pct = (secondsLeft / TOTP_PERIOD) * 100;
  const color = secondsLeft <= 5 ? '#e74c3c' : secondsLeft <= 10 ? '#e67e22' : '#2ecc71';

  return (
    <div
      role="timer"
      aria-label={`TOTP code expires in ${secondsLeft} seconds`}
      style={{ display: 'flex', alignItems: 'center', gap: '10px', margin: '12px 0' }}
    >
      {/* Circular progress */}
      <svg width="40" height="40" aria-hidden="true">
        <circle cx="20" cy="20" r="16" fill="none" stroke="#eee" strokeWidth="4" />
        <circle
          cx="20" cy="20" r="16"
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeDasharray={`${2 * Math.PI * 16}`}
          strokeDashoffset={`${2 * Math.PI * 16 * (1 - pct / 100)}`}
          strokeLinecap="round"
          transform="rotate(-90 20 20)"
          style={{ transition: 'stroke-dashoffset 0.5s linear, stroke 0.3s' }}
        />
        <text x="20" y="25" textAnchor="middle" fontSize="11" fill={color} fontWeight="bold">
          {secondsLeft}
        </text>
      </svg>
      <span style={{ fontSize: '0.85rem', color: '#555' }}>
        Code refreshes in <strong style={{ color }}>{secondsLeft}s</strong>
      </span>
    </div>
  );
}

export default function MfaSetup() {
  const [step, setStep] = useState('loading'); // loading | enroll | verify | done | error
  const [qrDataURL, setQrDataURL] = useState('');
  const [secret, setSecret] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [token, setToken] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Fetch MFA setup data from backend
  useEffect(() => {
    let cancelled = false;
    client.get('/auth/mfa/setup')
      .then(({ data }) => {
        if (cancelled) return;
        // data.qrDataURL is a base64 PNG data URL — rendered as <img>, not innerHTML
        setQrDataURL(data.qrDataURL);
        setSecret(data.secret);
        setBackupCodes(data.backupCodes || []);
        setStep('enroll');
      })
      .catch(() => {
        if (!cancelled) setStep('error');
      });
    return () => { cancelled = true; };
  }, []);

  const handleVerify = useCallback(async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSubmitting(true);
    try {
      await client.post('/auth/mfa/verify', { token: token.trim() });
      setStep('done');
    } catch (err) {
      setErrorMsg(err.message || 'Invalid code. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }, [token]);

  // ── Render ────────────────────────────────────────────────────────────────

  if (step === 'loading') {
    return <p style={styles.info}>Loading MFA setup…</p>;
  }

  if (step === 'error') {
    return <p style={styles.error}>Failed to load MFA setup. Please try again.</p>;
  }

  if (step === 'done') {
    return (
      <div style={styles.card}>
        <h2 style={styles.heading}>✓ MFA Enabled</h2>
        <p style={styles.info}>
          Two-factor authentication is now active on your account.
        </p>
        {backupCodes.length > 0 && (
          <>
            <p style={{ ...styles.info, fontWeight: 600, color: '#c0392b' }}>
              Save these backup codes now. They will not be shown again.
            </p>
            <ul style={styles.codeList} aria-label="Backup codes">
              {backupCodes.map((code, i) => (
                <li key={i} style={styles.codeItem}>
                  {/* textContent via JSX — safe */}
                  <code>{code}</code>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    );
  }

  return (
    <div style={styles.card}>
      <h1 style={styles.heading}>Set Up Two-Factor Authentication</h1>

      {/* Step 1: Scan QR */}
      <section aria-labelledby="scan-heading">
        <h2 id="scan-heading" style={styles.subheading}>
          1. Scan with your authenticator app
        </h2>
        {qrDataURL && (
          <img
            src={qrDataURL}
            alt="TOTP QR code — scan with Google Authenticator or Authy"
            style={styles.qr}
            width={180}
            height={180}
          />
        )}
        <p style={styles.info}>
          Can&apos;t scan? Enter this secret manually:
        </p>
        <code style={styles.secret} aria-label="Manual TOTP secret">
          {secret}
        </code>
      </section>

      {/* Step 2: Countdown */}
      <section aria-labelledby="timer-heading">
        <h2 id="timer-heading" style={styles.subheading}>
          2. Your code refreshes every 30 seconds
        </h2>
        <TOTPCountdown />
      </section>

      {/* Step 3: Verify */}
      <section aria-labelledby="verify-heading">
        <h2 id="verify-heading" style={styles.subheading}>
          3. Enter the 6-digit code to confirm setup
        </h2>
        <form onSubmit={handleVerify} noValidate>
          <input
            type="text"
            inputMode="numeric"
            pattern="\d{6}"
            maxLength={6}
            value={token}
            onChange={(e) => setToken(e.target.value.replace(/\D/g, ''))}
            placeholder="000000"
            autoComplete="one-time-code"
            aria-label="6-digit TOTP code"
            required
            style={styles.input}
          />
          {errorMsg && (
            <p role="alert" style={styles.error}>
              {errorMsg}
            </p>
          )}
          <button
            type="submit"
            disabled={submitting || token.length !== 6}
            style={styles.button}
          >
            {submitting ? 'Verifying…' : 'Enable MFA'}
          </button>
        </form>
      </section>
    </div>
  );
}

const styles = {
  card: {
    maxWidth: 480,
    margin: '2rem auto',
    padding: '2rem',
    border: '1px solid #ddd',
    borderRadius: 8,
    fontFamily: 'system-ui, sans-serif',
    background: '#fff',
  },
  heading: { fontSize: '1.4rem', marginBottom: '1rem', color: '#1a1a2e' },
  subheading: { fontSize: '1rem', color: '#333', marginTop: '1.5rem' },
  qr: { display: 'block', margin: '1rem 0', border: '1px solid #eee', borderRadius: 4 },
  secret: {
    display: 'block',
    padding: '8px 12px',
    background: '#f5f5f5',
    borderRadius: 4,
    letterSpacing: '0.15em',
    fontSize: '0.9rem',
    margin: '6px 0',
    wordBreak: 'break-all',
  },
  input: {
    display: 'block',
    width: '100%',
    padding: '10px 12px',
    fontSize: '1.2rem',
    letterSpacing: '0.3em',
    textAlign: 'center',
    border: '1.5px solid #bbb',
    borderRadius: 6,
    marginBottom: '10px',
    boxSizing: 'border-box',
  },
  button: {
    width: '100%',
    padding: '10px',
    background: '#1a1a2e',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    fontSize: '1rem',
    cursor: 'pointer',
  },
  info: { fontSize: '0.88rem', color: '#555', margin: '6px 0' },
  error: { color: '#e74c3c', fontSize: '0.85rem', margin: '6px 0' },
  codeList: { listStyle: 'none', padding: 0, margin: '10px 0', columns: 2, gap: '10px' },
  codeItem: {
    padding: '6px 10px',
    background: '#f9f9f9',
    border: '1px solid #eee',
    borderRadius: 4,
    fontFamily: 'monospace',
    fontSize: '0.9rem',
    marginBottom: 6,
  },
};