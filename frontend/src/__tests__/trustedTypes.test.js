/**
 * trustedTypes.test.js — Member C
 * Tests for the Trusted Types policy and CSP helper.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock DOMPurify ────────────────────────────────────────────────────────────
vi.mock('dompurify', () => ({
  default: {
    sanitize: vi.fn((input) => input.replace(/<script.*?>.*?<\/script>/gi, '')),
    addHook: vi.fn(),
    version: '3.0.0',
  },
}));

// ── Mock window.trustedTypes ──────────────────────────────────────────────────
function mockTrustedTypes() {
  const policies = {};
  window.trustedTypes = {
    createPolicy: (name, rules) => {
      if (policies[name]) throw new Error(`Policy "${name}" already been created`);
      policies[name] = rules;
      return rules;
    },
    defaultPolicy: null,
    getPolicyNames: () => Object.keys(policies),
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('installTrustedTypesPolicy', () => {
  beforeEach(() => {
    vi.resetModules();
    delete window.trustedTypes;
  });

  it('returns null and warns when Trusted Types not supported', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const result = installTrustedTypesPolicy();
    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Not supported'));
    consoleSpy.mockRestore();
  });

  it('installs policy when Trusted Types is supported', async () => {
    mockTrustedTypes();
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const policy = installTrustedTypesPolicy();
    expect(policy).not.toBeNull();
    expect(typeof policy.createHTML).toBe('function');
  });

  it('createHTML sanitizes script tags', async () => {
    mockTrustedTypes();
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const policy = installTrustedTypesPolicy();
    const result = policy.createHTML('<p>Hello</p><script>alert(1)</script>');
    expect(result).not.toContain('<script>');
    expect(result).toContain('<p>Hello</p>');
  });

  it('createScript throws unconditionally', async () => {
    mockTrustedTypes();
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const policy = installTrustedTypesPolicy();
    expect(() => policy.createScript('alert(1)')).toThrow(
      'Dynamic script creation is forbidden'
    );
  });

  it('createScriptURL blocks cross-origin URLs', async () => {
    mockTrustedTypes();
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://myapp.com' },
      writable: true,
    });
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const policy = installTrustedTypesPolicy();
    expect(() => policy.createScriptURL('https://evil.com/bad.js')).toThrow(
      'Cross-origin script URL blocked'
    );
  });

  it('createScriptURL allows same-origin URLs', async () => {
    mockTrustedTypes();
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://myapp.com', href: 'https://myapp.com/' },
      writable: true,
    });
    const { installTrustedTypesPolicy } = await import('../security/trustedTypes.js');
    const policy = installTrustedTypesPolicy();
    // Same-origin should not throw
    expect(() => policy.createScriptURL('https://myapp.com/main.js')).not.toThrow();
  });
});

describe('toTrustedHTML', () => {
  it('sanitizes input even without Trusted Types support', async () => {
    delete window.trustedTypes;
    const { toTrustedHTML } = await import('../security/trustedTypes.js');
    const result = toTrustedHTML('<p>Safe</p><script>evil()</script>');
    expect(result).not.toContain('<script>');
  });
});