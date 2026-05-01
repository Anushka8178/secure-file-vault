/**
 * files.api.js — Member C
 * File-related API calls consumed by Upload page and FileTable.
 * Member B owns /upload endpoints; this only calls them.
 */
import client from './client.js';

export const filesApi = {
  /** GET /api/files — user's own files */
  list: () => client.get('/api/files'),

  /** GET /api/files/:id/status — scan status */
  getStatus: (fileId) => client.get(`/api/files/${fileId}/status`),

  /** DELETE /api/files/:id */
  delete: (fileId) => client.delete(`/api/files/${fileId}`),

  /**
   * POST /api/links — generate expiring signed download link
   * @param {string} fileId
   * @param {number} ttl — seconds
   * @param {boolean} bindIP
   */
  createLink: (fileId, ttl, bindIP = false) =>
    client.post('/api/links', { fileId, ttl, bindIP }),

  /** DELETE /api/links/:linkId — revoke a signed link */
  revokeLink: (linkId) => client.delete(`/api/links/${linkId}`),
};