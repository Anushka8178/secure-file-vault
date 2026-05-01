/**
 * Upload.test.jsx — Member C
 * Tests for the Upload page — focuses on security behaviours:
 *   - File size limit enforced client-side
 *   - Disallowed file types rejected
 *   - No localStorage usage during upload
 *   - Progress tracked correctly
 *   - Scan status displayed from poll response
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock('../hooks/useUpload.js', () => ({
  useUpload: vi.fn(),
}));

vi.mock('../security/domPurify.config.js', () => ({
  sanitizePlainText: (s) => s,
}));

import Upload from '../pages/Upload.jsx';
import { useUpload } from '../hooks/useUpload.js';

function renderUpload() {
  return render(
    <MemoryRouter>
      <Upload />
    </MemoryRouter>
  );
}

function makeFile(name, sizeBytes, type = 'application/pdf') {
  const file = new File(['x'.repeat(sizeBytes)], name, { type });
  Object.defineProperty(file, 'size', { value: sizeBytes });
  return file;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Upload — security behaviours', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();

    // Default useUpload mock — idle state
    useUpload.mockReturnValue({
      upload:      vi.fn().mockResolvedValue({ file: { id: 'abc123', name: 'test.pdf', status: 'pending' } }),
      progress:    0,
      uploading:   false,
      error:       '',
      reset:       vi.fn(),
    });
  });

  it('renders upload dropzone and submit button', () => {
    renderUpload();
    expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/file drop zone/i)).toBeInTheDocument();
  });

  it('submit button is disabled when no file is selected', () => {
    renderUpload();
    expect(screen.getByRole('button', { name: /upload/i })).toBeDisabled();
  });

  it('SECURITY: rejects files larger than 5 MB', async () => {
    renderUpload();
    const oversizedFile = makeFile('big.pdf', 6 * 1024 * 1024); // 6 MB
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, oversizedFile);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/too large/i);
    });
    expect(screen.getByRole('button', { name: /upload/i })).toBeDisabled();
  });

  it('SECURITY: rejects disallowed file types (.exe)', async () => {
    renderUpload();
    const exeFile = makeFile('malware.exe', 1024, 'application/octet-stream');
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, exeFile);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/not allowed/i);
    });
  });

  it('SECURITY: rejects disallowed file types (.js)', async () => {
    renderUpload();
    const jsFile = makeFile('script.js', 1024, 'application/javascript');
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, jsFile);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/not allowed/i);
    });
  });

  it('accepts a valid PDF under 5 MB', async () => {
    renderUpload();
    const validFile = makeFile('document.pdf', 1024 * 1024); // 1 MB
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, validFile);

    await waitFor(() => {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: /upload/i })).not.toBeDisabled();
    });
  });

  it('displays filename via textContent — not innerHTML', async () => {
    renderUpload();
    const xssFile = makeFile('<img src=x onerror=alert(1)>.pdf', 1024);
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, xssFile);

    // File name must appear as text, never executed as HTML
    const dropzone = screen.getByLabelText(/file drop zone/i);
    // sanitizePlainText is mocked as identity here; in real app it strips tags
    expect(dropzone.innerHTML).not.toContain('onerror');
  });

  it('SECURITY: does not write to localStorage during upload', async () => {
    const setItemSpy = vi.spyOn(Storage.prototype, 'setItem');
    renderUpload();

    const validFile = makeFile('doc.pdf', 512 * 1024);
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, validFile);
    fireEvent.click(screen.getByRole('button', { name: /upload/i }));

    await waitFor(() => expect(setItemSpy).not.toHaveBeenCalled());
  });

  it('shows upload result after successful upload', async () => {
    renderUpload();
    const validFile = makeFile('report.pdf', 512 * 1024);
    const input = screen.getByLabelText(/file input/i);
    await userEvent.upload(input, validFile);
    fireEvent.click(screen.getByRole('button', { name: /upload/i }));

    await waitFor(() => {
      expect(screen.getByRole('status')).toBeInTheDocument();
    });
  });

  it('shows progress bar while uploading', () => {
    useUpload.mockReturnValue({
      upload:    vi.fn(),
      progress:  55,
      uploading: true,
      error:     '',
      reset:     vi.fn(),
    });
    renderUpload();
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '55');
  });

  it('displays upload error from hook', () => {
    useUpload.mockReturnValue({
      upload:    vi.fn(),
      progress:  0,
      uploading: false,
      error:     'Network error during upload.',
      reset:     vi.fn(),
    });
    renderUpload();
    expect(screen.getByRole('alert')).toHaveTextContent(/network error/i);
  });
});