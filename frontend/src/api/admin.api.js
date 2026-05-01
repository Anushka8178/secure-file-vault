/**
 * admin.api.js — Member C
 * Admin panel API calls. Role enforcement is on the backend (Member A).
 * This file only makes the HTTP calls — it does NOT enforce roles.
 */
import client from './client.js';

export const adminApi = {
  /** GET /api/admin/files — all files (admin only) */
  listAllFiles: () => client.get('/api/admin/files'),

  /** DELETE /api/admin/files/:id */
  deleteFile: (fileId) => client.delete(`/api/admin/files/${fileId}`),

  /** GET /api/admin/users — user list (admin only) */
  listUsers: () => client.get('/api/admin/users'),

  /** PATCH /api/admin/users/:id/role */
  updateUserRole: (userId, role) =>
    client.patch(`/api/admin/users/${userId}/role`, { role }),
};