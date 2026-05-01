/**
 * domPurify.config.js — Member C Security
 * Centralized DOMPurify configuration for the application.
 *
 * Rules:
 * - Never use innerHTML without going through sanitize() from this module.
 * - All React components must use textContent / JSX (which escapes by default).
 * - This config is only needed for the rare case of rendering user-supplied
 *   rich text (e.g., audit log descriptions, admin notes).
 *
 * No backend interaction. Pure frontend sanitization layer.
 */

import DOMPurify from 'dompurify';

/* ─────────────────────────────────────────────
   Base config shared across all profiles
───────────────────────────────────────────── */
const BASE_CONFIG = {
  // Never allow data attributes — common XSS vector
  ALLOW_DATA_ATTR: false,

  // Always return a string, never a DOM node
  RETURN_DOM: false,
  RETURN_DOM_FRAGMENT: false,

  // Wrap output in <body> so stray top-level tags are contained
  FORCE_BODY: true,

  // Remove comments (can contain sensitive data or IE conditional exploits)
  REMOVE_COMMENTS: true,

  // Tags that are ALWAYS forbidden regardless of profile
  FORBID_TAGS: [
    'script',
    'style',   // inline styles can be used for CSS injection
    'iframe',
    'frame',
    'frameset',
    'object',
    'embed',
    'applet',
    'form',
    'input',
    'button',
    'textarea',
    'select',
    'option',
    'link',    // rel=import, prefetch, etc.
    'meta',
    'base',
    'svg',     // SVG XSS vectors; use profile below to allow safe SVG
    'math',
  ],

  // Event handler attributes always forbidden
  FORBID_ATTR: [
    'onerror', 'onload', 'onclick', 'ondblclick',
    'onmouseover', 'onmouseout', 'onmousemove',
    'onfocus', 'onblur', 'onchange', 'onsubmit',
    'onreset', 'onselect', 'onkeydown', 'onkeyup',
    'onkeypress', 'oncontextmenu', 'oncopy', 'oncut',
    'onpaste', 'onwheel', 'ondrag', 'ondrop',
    'onscroll', 'onresize', 'onhashchange',
    // srcdoc / xlink:href — XSS vectors
    'srcdoc', 'xlink:href',
    // CSS expression injection
    'style',
  ],
};

/* ─────────────────────────────────────────────
   Profile: PLAIN TEXT
   Use for: usernames, filenames, any single-line user input
   Strips ALL HTML — returns plain text only.
───────────────────────────────────────────── */
const PLAIN_TEXT_CONFIG = {
  ...BASE_CONFIG,
  ALLOWED_TAGS: [],   // no tags at all
  ALLOWED_ATTR: [],
};

/* ─────────────────────────────────────────────
   Profile: RICH TEXT (audit notes, descriptions)
   Use for: admin-entered descriptions, audit log notes
   Allows basic formatting only.
───────────────────────────────────────────── */
const RICH_TEXT_CONFIG = {
  ...BASE_CONFIG,
  USE_PROFILES: { html: true },
  ALLOWED_TAGS: [
    'b', 'i', 'em', 'strong', 'u', 's',
    'p', 'br', 'hr',
    'ul', 'ol', 'li',
    'blockquote', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a',      // href only — target and rel enforced below
    'span',
  ],
  ALLOWED_ATTR: [
    'href',   // <a href> — protocol enforced via hook below
    'target', // forced to _blank by hook
    'rel',    // forced to noopener noreferrer by hook
    'class',  // CSS classes (no inline style)
    'lang',   // accessibility
    'dir',    // bidi text direction
  ],
};

/* ─────────────────────────────────────────────
   DOMPurify Hooks — applied globally once
───────────────────────────────────────────── */
let _hooksInstalled = false;

function installHooks() {
  if (_hooksInstalled) return;
  _hooksInstalled = true;

  /**
   * afterSanitizeAttributes:
   * - Force all <a> links to open in a new tab safely.
   * - Block javascript: / data: / vbscript: href values.
   */
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A') {
      // Block dangerous protocols
      const href = node.getAttribute('href') || '';
      const lowerHref = href.trim().toLowerCase();
      const BLOCKED_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:'];
      if (BLOCKED_PROTOCOLS.some((p) => lowerHref.startsWith(p))) {
        node.removeAttribute('href');
      } else {
        // Force safe external link behaviour
        node.setAttribute('target', '_blank');
        node.setAttribute('rel', 'noopener noreferrer');
      }
    }
  });

  /**
   * uponSanitizeElement:
   * Log any element that was stripped (dev only).
   */
  if (import.meta.env.DEV) {
    DOMPurify.addHook('uponSanitizeElement', (node, data) => {
      if (data.allowedTags && !data.allowedTags[data.tagName]) {
        console.debug(`[DOMPurify] Stripped element: <${data.tagName}>`);
      }
    });
  }
}

/* ─────────────────────────────────────────────
   Public API
───────────────────────────────────────────── */

/**
 * Sanitize plain text input (strips ALL HTML).
 * Use for: usernames, file names, search queries, any single-line value.
 *
 * @param {string} dirty
 * @returns {string} clean plain text
 */
export function sanitizePlainText(dirty) {
  installHooks();
  return DOMPurify.sanitize(dirty, PLAIN_TEXT_CONFIG);
}

/**
 * Sanitize rich HTML content.
 * Use ONLY when you must render user-supplied HTML (e.g., audit notes).
 * The result must still be assigned via Trusted Types (trustedTypes.js).
 *
 * @param {string} dirty
 * @returns {string} sanitized HTML string
 */
export function sanitizeRichText(dirty) {
  installHooks();
  return DOMPurify.sanitize(dirty, RICH_TEXT_CONFIG);
}

/**
 * Returns true if a string contains any HTML tags.
 * Useful for deciding which sanitizer to apply.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function containsHTML(value) {
  return /<[a-z][\s\S]*>/i.test(value);
}

/**
 * DOMPurify version info — for audit / security headers.
 */
export const DOMPURIFY_VERSION = DOMPurify.version;