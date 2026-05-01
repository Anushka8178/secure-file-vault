/**
 * trustedTypes.js — Member C Security
 * Enforces Trusted Types API to prevent DOM XSS.
 * Must be imported FIRST in main.jsx before any rendering.
 *
 * Policy: only DOMPurify-sanitized strings may be assigned
 * to sink properties (innerHTML, outerHTML, insertAdjacentHTML, etc.)
 *
 * No backend interaction. Pure frontend security layer.
 */

import DOMPurify from 'dompurify';

const POLICY_NAME = 'default';

/**
 * Creates and registers the Trusted Types default policy.
 * If the browser does not support Trusted Types, a console warning
 * is emitted and the app continues (graceful degradation).
 *
 * @returns {TrustedTypePolicy|null}
 */
export function installTrustedTypesPolicy() {
  // Check for Trusted Types API support
  if (
    typeof window === 'undefined' ||
    !window.trustedTypes ||
    !window.trustedTypes.createPolicy
  ) {
    console.warn(
      '[TrustedTypes] Not supported in this browser. ' +
        'DOM XSS protection via Trusted Types is unavailable.'
    );
    return null;
  }

  // Avoid re-registering if already defined (e.g., HMR in dev)
  try {
    const policy = window.trustedTypes.createPolicy(POLICY_NAME, {
      /**
       * createHTML — the only allowed path to set innerHTML.
       * All HTML must pass through DOMPurify before being trusted.
       */
      createHTML(dirty) {
        return DOMPurify.sanitize(dirty, {
          USE_PROFILES: { html: true },
          FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form'],
          FORBID_ATTR: [
            'onerror',
            'onload',
            'onclick',
            'onmouseover',
            'onfocus',
            'onblur',
            'onchange',
            'onsubmit',
            'onkeydown',
            'onkeyup',
            'onkeypress',
          ],
          ALLOW_DATA_ATTR: false,
          FORCE_BODY: true,
        });
      },

      /**
       * createScript — block all inline script creation.
       * Throw unconditionally; no dynamic scripts are permitted.
       */
      createScript(_script) {
        throw new Error(
          '[TrustedTypes] Dynamic script creation is forbidden by security policy.'
        );
      },

      /**
       * createScriptURL — only allow same-origin URLs.
       * Prevents loading remote scripts via Worker, importScripts, etc.
       */
      createScriptURL(url) {
        const parsed = new URL(url, window.location.origin);
        if (parsed.origin !== window.location.origin) {
          throw new Error(
            `[TrustedTypes] Cross-origin script URL blocked: ${url}`
          );
        }
        return parsed.href;
      },
    });

    console.info('[TrustedTypes] Default policy installed successfully.');
    return policy;
  } catch (err) {
    // Policy may already exist (dev HMR reload)
    if (err.message && err.message.includes('already been created')) {
      console.info('[TrustedTypes] Policy already registered, skipping.');
      return null;
    }
    console.error('[TrustedTypes] Failed to install policy:', err);
    throw err;
  }
}

/**
 * Converts a raw string to a TrustedHTML value using the default policy.
 * Use this ONLY when you must set innerHTML (e.g., DOMPurify-sanitized rich text).
 * Prefer textContent everywhere else.
 *
 * @param {string} dirty - Untrusted HTML string
 * @returns {TrustedHTML|string} TrustedHTML in supported browsers, plain sanitized string otherwise
 */
export function toTrustedHTML(dirty) {
  if (window.trustedTypes && window.trustedTypes.defaultPolicy) {
    return window.trustedTypes.defaultPolicy.createHTML(dirty);
  }
  // Fallback: still sanitize even without Trusted Types support
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form'],
    ALLOW_DATA_ATTR: false,
  });
}

/**
 * Safe alternative to element.innerHTML = value.
 * Always sanitizes before writing to DOM.
 *
 * @param {HTMLElement} element
 * @param {string} dirty
 */
export function safeSetInnerHTML(element, dirty) {
  if (!element || !(element instanceof HTMLElement)) {
    throw new Error('[TrustedTypes] safeSetInnerHTML: invalid element');
  }
  element.innerHTML = toTrustedHTML(dirty);
}