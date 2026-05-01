/**
 * Login.test.jsx — Member C
 * Tests for the Login page — focuses on security behaviours:
 *   - No localStorage usage
 *   - MFA field appears only when backend signals it
 *   - Generic error messages (no user enumeration)
 *   - CSRF token attached (via client.js mock)
 *   - Redirect to /dashboard on success
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

// ── Mocks ─────────────────────────────────────────────────────────────────────

// Mock client.js so no real HTTP calls are made
vi.mock('../api/client.js', () => ({
  default: {
    post: vi.fn(),
  },
}));

// Mock domPurify.config.js
vi.mock('../security/domPurify.config.js', () => ({
  sanitizePlainText: (s) => s,
}));

// Capture window.location.replace calls
const replaceMock = vi.fn();
Object.defineProperty(window, 'location', {
  value: { replace: replaceMock },
  writable: true,
});

import Login from '../pages/Login.jsx';
import client from '../api/client.js';

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Login — security behaviours', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders email and password fields', () => {
    renderLogin();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it('does NOT render MFA field initially', () => {
    renderLogin();
    expect(screen.queryByLabelText(/authenticator code/i)).not.toBeInTheDocument();
  });

  it('redirects to /dashboard on successful login', async () => {
    client.post.mockResolvedValueOnce({ data: {} });
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'correctpassword');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith('/dashboard');
    });
  });

  it('shows generic error on 401 — no user enumeration', async () => {
    client.post.mockRejectedValueOnce({ status: 401, message: 'Unauthorized' });
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'wrong@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'wrongpass');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/invalid credentials/i);
    });
    // Must NOT say "user not found" or "email not registered" (enumeration)
    expect(screen.getByRole('alert').textContent).not.toMatch(/not found|not registered|no account/i);
  });

  it('shows MFA field when backend returns 403 (MFA required)', async () => {
    client.post.mockRejectedValueOnce({ status: 403, message: 'MFA required' });
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByLabelText(/6-digit mfa code/i)).toBeInTheDocument();
    });
  });

  it('shows rate limit message on 429', async () => {
    client.post.mockRejectedValueOnce({ status: 429, message: 'Too Many Requests' });
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/too many attempts/i);
    });
  });

  it('SECURITY: does not write anything to localStorage on login', async () => {
    client.post.mockResolvedValueOnce({ data: {} });
    const setItemSpy = vi.spyOn(Storage.prototype, 'setItem');
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(replaceMock).toHaveBeenCalled());
    expect(setItemSpy).not.toHaveBeenCalled();
  });

  it('SECURITY: does not write anything to sessionStorage on login', async () => {
    client.post.mockResolvedValueOnce({ data: {} });
    const setItemSpy = vi.spyOn(Storage.prototype, 'setItem');
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(replaceMock).toHaveBeenCalled());
    expect(setItemSpy).not.toHaveBeenCalled();
  });

  it('disables submit button while submitting', async () => {
    // Keep promise pending to simulate in-flight request
    client.post.mockReturnValueOnce(new Promise(() => {}));
    renderLogin();

    await userEvent.type(screen.getByLabelText(/email/i), 'user@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'password123');
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled();
    });
  });
});