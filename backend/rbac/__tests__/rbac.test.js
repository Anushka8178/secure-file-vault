const { ROLE_HIERARCHY } = require('../roles');
const { getPermissionsForRole, hasPermission } = require('../permissions');
const { checkPolicy } = require('../abac.policy');

describe('RBAC - Role Hierarchy', () => {
  test('SuperAdmin > Admin > User > ReadOnly', () => {
    expect(ROLE_HIERARCHY.SuperAdmin).toBeGreaterThan(ROLE_HIERARCHY.Admin);
    expect(ROLE_HIERARCHY.Admin).toBeGreaterThan(ROLE_HIERARCHY.User);
    expect(ROLE_HIERARCHY.User).toBeGreaterThan(ROLE_HIERARCHY.ReadOnly);
  });
});

describe('RBAC - Permissions', () => {
  test('User inherits ReadOnly permissions', () => {
    const perms = getPermissionsForRole('User');
    expect(perms).toContain('file:read');
    expect(perms).toContain('file:upload');
  });

  test('Admin has audit:read, User does not', () => {
    expect(hasPermission('Admin', 'audit:read')).toBe(true);
    expect(hasPermission('User', 'audit:read')).toBe(false);
  });

  test('SuperAdmin has all permissions', () => {
    expect(hasPermission('SuperAdmin', 'user:delete')).toBe(true);
    expect(hasPermission('SuperAdmin', 'file:read')).toBe(true);
  });
});

describe('ABAC Policies', () => {
  const adminUser = { id: 'admin1', role: 'Admin' };
  const normalUser = { id: 'user1', role: 'User' };
  const fileOwnedByUser = { ownerId: { toString: () => 'user1' } };
  const fileOwnedByOther = { ownerId: { toString: () => 'other' } };

  test('admin can download any file', () => {
    expect(checkPolicy(adminUser, 'file:download', fileOwnedByOther)).toBe(true);
  });

  test('user can download own file', () => {
    expect(checkPolicy(normalUser, 'file:download', fileOwnedByUser)).toBe(true);
  });

  test('user cannot download others file', () => {
    expect(checkPolicy(normalUser, 'file:download', fileOwnedByOther)).toBe(false);
  });
});
