/**
 * useAuth.js — Member C
 * Auth state hook.
 *
 * Security rules:
 * - NO localStorage or sessionStorage — auth state from server only
 * - User object fetched from /auth/me on mount (validates cookie server-side)
 * - Logout calls POST /auth/logout (clears HttpOnly cookie server-side)
 * - No JWT decoding client-side — server is source of truth
 *
 * Consumes:
 *   GET  /auth/me      → { id, email, username, role }
 *   POST /auth/logout  → clears session cookie
 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import client from '../api/client.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);       // null = unknown, false = unauthenticated
  const [loading, setLoading] = useState(true);

  // Validate session on mount — no token in localStorage; server checks cookie
  useEffect(() => {
    let cancelled = false;
    client.get('/auth/me')
      .then(({ data }) => {
        if (!cancelled) setUser(data.user || false);
      })
      .catch(() => {
        // 401 intercepted in client.js; here we just mark unauthenticated
        if (!cancelled) setUser(false);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const logout = useCallback(async () => {
    try {
      await client.post('/auth/logout');
    } finally {
      setUser(false);
      // Hard redirect — clears all React state; cookie cleared by backend
      window.location.replace('/login');
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, setUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * useAuth — consume auth context in any component.
 *
 * Returns:
 *   user    {object|false|null} — user object, false if unauthed, null while loading
 *   loading {boolean}
 *   logout  {fn}
 *   setUser {fn}               — used after login to update state without page reload
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within <AuthProvider>');
  }
  return ctx;
}