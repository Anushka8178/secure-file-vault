/**
 * PasswordStrength.jsx — Member C
 * Password strength meter using zxcvbn.
 *
 * Security rules:
 * - No innerHTML — all text via JSX (React escapes by default)
 * - No eval / no dynamic code
 * - zxcvbn runs client-side only; password never sent just for scoring
 *
 * Props:
 *   password {string} — current password value from controlled input
 */

import { useMemo } from 'react';
import zxcvbn from 'zxcvbn';

const LEVELS = [
  { label: 'Very Weak', color: '#e74c3c', bg: '#fdecea' },
  { label: 'Weak',      color: '#e67e22', bg: '#fef3e2' },
  { label: 'Fair',      color: '#f1c40f', bg: '#fefde2' },
  { label: 'Strong',    color: '#2ecc71', bg: '#eafaf1' },
  { label: 'Very Strong', color: '#27ae60', bg: '#d5f5e3' },
];

export default function PasswordStrength({ password }) {
  const result = useMemo(() => {
    if (!password) return null;
    return zxcvbn(password);
  }, [password]);

  if (!password) return null;

  const score = result.score; // 0–4
  const level = LEVELS[score];
  const fillPercent = ((score + 1) / 5) * 100;

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Password strength: ${level.label}`}
      style={{ marginTop: '0.5rem' }}
    >
      {/* Segmented bar */}
      <div
        style={{
          display: 'flex',
          gap: '4px',
          marginBottom: '6px',
        }}
        aria-hidden="true"
      >
        {LEVELS.map((l, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              height: '5px',
              borderRadius: '3px',
              backgroundColor: i <= score ? level.color : '#e0e0e0',
              transition: 'background-color 0.3s ease',
            }}
          />
        ))}
      </div>

      {/* Label */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.78rem',
        }}
      >
        <span style={{ color: level.color, fontWeight: 600 }}>
          {level.label}
        </span>
        {result.feedback.warning && (
          <span style={{ color: '#666', fontStyle: 'italic' }}>
            {/* textContent via JSX — safe, no innerHTML */}
            {result.feedback.warning}
          </span>
        )}
      </div>

      {/* Suggestions */}
      {result.feedback.suggestions.length > 0 && (
        <ul
          style={{
            margin: '6px 0 0 0',
            paddingLeft: '1.2rem',
            fontSize: '0.75rem',
            color: '#555',
          }}
        >
          {result.feedback.suggestions.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
      )}

      {/* Crack time hint */}
      <p
        style={{
          fontSize: '0.72rem',
          color: '#888',
          margin: '4px 0 0 0',
        }}
      >
        Estimated crack time:{' '}
        <strong>
          {result.crack_times_display.offline_slow_hashing_1e4_per_second}
        </strong>
      </p>
    </div>
  );
}