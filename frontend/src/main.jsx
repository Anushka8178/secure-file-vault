/**
 * main.jsx — Application Entry Point
 * Member C Security: Trusted Types + CSP violation reporter
 * must be bootstrapped HERE before React renders anything.
 *
 * Order matters:
 *   1. Install Trusted Types policy  ← blocks DOM XSS sinks
 *   2. Install CSP violation reporter ← catches policy violations
 *   3. Mount React app
 *
 * No backend calls happen here.
 */

// ── 1. Security bootstrap (must be first) ──────────────────────────────────
import { installTrustedTypesPolicy } from './security/trustedTypes.js';
import { installCSPViolationReporter } from './security/csp.js';

// Install Trusted Types default policy before ANY DOM manipulation
installTrustedTypesPolicy();

// Start listening for CSP violations immediately
installCSPViolationReporter();

// ── 2. React + App ─────────────────────────────────────────────────────────
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';

const container = document.getElementById('root');

if (!container) {
  throw new Error(
    '[main] Root element #root not found. Check public/index.html.'
  );
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);