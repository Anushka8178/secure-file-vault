/**
 * vite.config.js — Member C Security
 * Build configuration focused on:
 *   - Subresource Integrity (SRI) hash generation for all output assets
 *   - No eval() / unsafe dynamic code in output (Content-Security-Policy compatible)
 *   - Source maps disabled in production (no code leakage)
 *   - Strict module resolution
 *
 * Does NOT configure backend routes — those are handled by nginx/backend team.
 */

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * vite-plugin-sri
 * Injects integrity="sha384-..." attributes on all <script> and <link rel="stylesheet">
 * tags in the built index.html.
 *
 * Install: npm install --save-dev vite-plugin-sri3
 *
 * NOTE: Use vite-plugin-sri3 (maintained fork) not the original vite-plugin-sri
 * which is unmaintained.
 */
import sri from 'vite-plugin-sri3';

export default defineConfig(({ mode }) => {
  const isProd = mode === 'production';

  return {
    plugins: [
      react(),

      // SRI: generates sha384 hashes for all emitted JS/CSS chunks
      sri({
        algorithms: ['sha384'],
      }),
    ],

    build: {
      // ── Output ─────────────────────────────────────────────────────────
      outDir: 'dist',
      assetsDir: 'assets',

      // ── Source Maps ────────────────────────────────────────────────────
      // No source maps in production — prevents source code leakage
      sourcemap: isProd ? false : 'inline',

      // ── Code Splitting ─────────────────────────────────────────────────
      rollupOptions: {
        output: {
          // Deterministic chunk naming for SRI caching
          entryFileNames: 'assets/[name].[hash].js',
          chunkFileNames: 'assets/[name].[hash].js',
          assetFileNames: 'assets/[name].[hash].[ext]',

          // Manual chunks — separate vendor bundle for better caching
          manualChunks: {
            vendor: ['react', 'react-dom'],
            dompurify: ['dompurify'],
          },
        },
      },

      // ── Security: no eval ──────────────────────────────────────────────
      // Rollup's default; explicitly stated for clarity.
      // Ensures output is compatible with CSP script-src without 'unsafe-eval'.
      minify: isProd ? 'esbuild' : false,

      // esbuild target — modern browsers that support Trusted Types
      target: ['chrome90', 'firefox88', 'safari15', 'edge90'],
    },

    esbuild: {
      // Drop console.log in production builds
      drop: isProd ? ['console', 'debugger'] : [],

      // Prevent eval usage in transpiled output
      // (esbuild never uses eval; this is documentation intent)
      supported: {
        'dynamic-import': true,
      },
    },

    // ── Dev Server ───────────────────────────────────────────────────────
    server: {
      // Proxy API calls to backend during development
      // This is read-only config — backend team owns the actual endpoints
      proxy: {
        '/api': {
          target: 'http://localhost:3000',
          changeOrigin: true,
          secure: false, // dev only; production goes through nginx TLS
        },
        '/auth': {
          target: 'http://localhost:3000',
          changeOrigin: true,
          secure: false,
        },
      },

      // Security headers in dev server (mirrors nginx for parity)
      headers: {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        // Note: no HSTS in dev (localhost), nginx handles it in prod
      },
    },

    // ── Preview (production build preview) ────────────────────────────────
    preview: {
      headers: {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
      },
    },
  };
});