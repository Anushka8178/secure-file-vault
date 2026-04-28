/**
 * Permission map per role
 * Each role inherits all permissions of roles below it
 */
const PERMISSIONS = {
  ReadOnly: [
    'file:read',
    'file:download',
    'profile:read',
  ],
  User: [
    'file:upload',
    'file:delete:own',
    'file:share:own',
    'profile:update',
    'session:manage:own',
  ],
  Admin: [
    'file:delete:any',
    'file:read:any',
    'user:read',
    'user:update:role',
    'audit:read',
    'admin:dashboard',
  ],
  SuperAdmin: [
    'user:delete',
    'user:impersonate',
    'system:configure',
    'audit:delete',
  ],
};

const { ROLE_HIERARCHY } = require('./roles');

/**
 * Get all permissions for a role (including inherited ones)
 */
const getPermissionsForRole = (role) => {
  const level = ROLE_HIERARCHY[role] ?? 0;
  const perms = new Set();
  for (const [r, rLevel] of Object.entries(ROLE_HIERARCHY)) {
    if (rLevel <= level) {
      (PERMISSIONS[r] || []).forEach((p) => perms.add(p));
    }
  }
  return [...perms];
};

/**
 * Check if role has a specific permission
 */
const hasPermission = (role, permission) => {
  return getPermissionsForRole(role).includes(permission);
};

module.exports = { PERMISSIONS, getPermissionsForRole, hasPermission };
