/**
 * csp.js — Member C Security
 * CSP Level 3 helpers for the frontend.
 *
 * The actual CSP header is delivered by nginx (infra/nginx/nginx.conf).
 * This module:
 *   1. Reads the per-request nonce injected by the server into index.html
 *   2. Exposes a helper so React components can apply the nonce to any
 *      <script> or <style> element they must create programmatically.
 *   3. Provides a violation reporter for CSP report-uri / report-to.
 *
 * NO inline styles or scripts should be added without the nonce.
 * NO eval(), new Function(), or setTimeout(string) is permitted.
 */

/**
 * Reads the CSP nonce that the server injects into the HTML document.
 *
 * The server (nginx + optional SSR middleware) sets a nonce attribute on
 * the bootstrap <script> tag:
 *   <script nonce="BASE64_NONCE" src="/main.js"></script>
 *
 * We retrieve it once and cache it for the page lifetime.
 *
 * @returns {string} nonce value or empty string if not found
 */
let _cachedNonce = '';

export function getNonce() {
  if (_cachedNonce) return _cachedNonce;

  // Try the meta tag first (simpler SSR injection point)
  const meta = document.querySelector('meta[name="csp-nonce"]');
  if (meta && meta.content) {
    _cachedNonce = meta.content;
    return _cachedNonce;
  }

  // Fallback: read nonce from the main entry script tag
  const scripts = document.querySelectorAll('script[nonce]');
  for (const script of scripts) {
    if (script.nonce) {
      _cachedNonce = script.nonce;
      return _cachedNonce;
    }
  }

  console.warn(
    '[CSP] No nonce found. Programmatic script/style creation will be blocked by CSP.'
  );
  return '';
}

/**
 * Creates a <script> element with the correct nonce.
 * Use instead of document.createElement('script') when dynamic
 * script injection is unavoidable (e.g., third-party analytics in dev).
 *
 * NOTE: In production, prefer bundled imports. This exists for edge cases.
 *
 * @param {string} src - same-origin script URL only
 * @returns {HTMLScriptElement}
 */
export function createNoncedScript(src) {
  const nonce = getNonce();
  if (!nonce) {
    throw new Error('[CSP] Cannot create nonced script: nonce unavailable.');
  }

  // Enforce same-origin
  const url = new URL(src, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new Error(`[CSP] Cross-origin script blocked: ${src}`);
  }

  const el = document.createElement('script');
  el.nonce = nonce;
  el.src = url.href;
  el.async = true;
  return el;
}

/**
 * Creates a <style> element with the correct nonce.
 * Use instead of injecting raw <style> when dynamic styles are needed.
 *
 * @param {string} css - CSS text to inject (sanitized by caller)
 * @returns {HTMLStyleElement}
 */
export function createNoncedStyle(css) {
  const nonce = getNonce();
  if (!nonce) {
    throw new Error('[CSP] Cannot create nonced style: nonce unavailable.');
  }

  const el = document.createElement('style');
  el.nonce = nonce;
  el.textContent = css; // textContent, never innerHTML
  return el;
}

/**
 * CSP violation handler.
 * Listens for securitypolicyviolation events and logs them.
 * In production, violations are also POSTed to /api/csp-report
 * (handled by backend; Member C only sets up the client side).
 *
 * Call once from main.jsx.
 */
export function installCSPViolationReporter() {
  document.addEventListener('securitypolicyviolation', (e) => {
    const report = {
      blockedURI: e.blockedURI,
      violatedDirective: e.violatedDirective,
      effectiveDirective: e.effectiveDirective,
      originalPolicy: e.originalPolicy,
      sourceFile: e.sourceFile,
      lineNumber: e.lineNumber,
      columnNumber: e.columnNumber,
      disposition: e.disposition,
      timestamp: new Date().toISOString(),
    };

    // Always log locally
    console.error('[CSP Violation]', report);

    // In production, report to backend endpoint
    if (import.meta.env.PROD) {
      // Use sendBeacon for reliability (fires even on page unload)
      const blob = new Blob([JSON.stringify({ 'csp-report': report })], {
        type: 'application/csp-report',
      });
      navigator.sendBeacon('/api/csp-report', blob);
    }
  });

  console.info('[CSP] Violation reporter installed.');
}

/**
 * CSP directive constants — mirrors what nginx delivers.
 * Kept here as documentation / for testing.
 *
 * Actual enforcement is always the nginx header.
 * This object is NOT injected into the DOM.
 */
export const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'strict-dynamic'", "'nonce-{NONCE}'"],
  'style-src': ["'self'", "'nonce-{NONCE}'"],
  'img-src': ["'self'", 'data:', 'blob:'],
  'font-src': ["'self'"],
  'connect-src': ["'self'"],
  'media-src': ["'none'"],
  'object-src': ["'none'"],
  'frame-src': ["'none'"],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
  'upgrade-insecure-requests': [],
  'block-all-mixed-content': [],
};