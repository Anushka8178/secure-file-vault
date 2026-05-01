/**
 * App.jsx — Member C
 * Root application component.
 *
 * Security rules:
 * - All protected routes guarded by PrivateRoute (checks auth via cookie, not localStorage)
 * - Admin route additionally guarded by role check
 * - No sensitive data stored in route state
 * - Redirects to /login on unauthenticated access
 *
 * Owns routes: /login, /register, /dashboard, /upload, /admin, /mfa-setup, /links
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth.js';

import Login        from './pages/Login.jsx';
import Register     from './pages/Register.jsx';
import Dashboard    from './pages/Dashboard.jsx';
import Upload       from './pages/Upload.jsx';
import Admin        from './pages/Admin.jsx';
import MfaSetup     from './pages/MfaSetup.jsx';
import LinkGenerator from './pages/LinkGenerator.jsx';

// ── PrivateRoute ──────────────────────────────────────────────────────────────
/**
 * Wraps routes that require authentication.
 * Reads auth state from server-validated cookie via useAuth hook.
 * Never reads localStorage or decodes a JWT client-side.
 *
 * @param {string} [requiredRole] — if provided, also checks user.role
 */
function PrivateRoute({ children, requiredRole }) {
  const { user, loading } = useAuth();

  // Still validating session with server
  if (loading) {
    return (
      <div style={styles.loading} role="status" aria-label="Loading…">
        <span>Loading…</span>
      </div>
    );
  }

  // Not authenticated → redirect to login
  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // Role check (e.g. admin-only routes)
  if (requiredRole && user.role !== requiredRole) {
    // Authenticated but wrong role → redirect to dashboard, not login
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}

// ── PublicRoute ───────────────────────────────────────────────────────────────
/**
 * Redirects authenticated users away from login/register pages.
 */
function PublicRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={styles.loading} role="status" aria-label="Loading…">
        <span>Loading…</span>
      </div>
    );
  }

  // Already authenticated → go to dashboard
  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}

// ── Routes ────────────────────────────────────────────────────────────────────
function AppRoutes() {
  return (
    <Routes>
      {/* Default → login */}
      <Route path="/" element={<Navigate to="/login" replace />} />

      {/* Public routes — redirect away if already logged in */}
      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />
      <Route
        path="/register"
        element={
          <PublicRoute>
            <Register />
          </PublicRoute>
        }
      />

      {/* Protected routes — require authentication */}
      <Route
        path="/dashboard"
        element={
          <PrivateRoute>
            <Dashboard />
          </PrivateRoute>
        }
      />
      <Route
        path="/upload"
        element={
          <PrivateRoute>
            <Upload />
          </PrivateRoute>
        }
      />
      <Route
        path="/mfa-setup"
        element={
          <PrivateRoute>
            <MfaSetup />
          </PrivateRoute>
        }
      />
      <Route
        path="/links"
        element={
          <PrivateRoute>
            <LinkGenerator />
          </PrivateRoute>
        }
      />

      {/* Admin-only route */}
      <Route
        path="/admin"
        element={
          <PrivateRoute requiredRole="admin">
            <Admin />
          </PrivateRoute>
        }
      />

      {/* 404 → redirect to dashboard or login */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <BrowserRouter>
      {/* AuthProvider validates session via /auth/me on mount.
          No tokens in localStorage — server-side cookie auth only. */}
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const styles = {
  loading: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: 'system-ui, sans-serif',
    color: '#888',
    fontSize: '1rem',
  },
};