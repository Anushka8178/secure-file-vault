const { ROLE_HIERARCHY } = require('./roles');

/**
 * ABAC Policy engine
 * Evaluates attribute-based policies beyond simple RBAC
 */
const POLICIES = {
  'file:download': (user, resource) => {
    // Admin+ can download anything
    if ((ROLE_HIERARCHY[user.role] ?? 0) >= ROLE_HIERARCHY['Admin']) return true;
    // Owner can download own files
    return resource.ownerId?.toString() === user.id;
  },
  'file:delete': (user, resource) => {
    if ((ROLE_HIERARCHY[user.role] ?? 0) >= ROLE_HIERARCHY['Admin']) return true;
    return resource.ownerId?.toString() === user.id;
  },
  'file:share': (user, resource) => {
    return resource.ownerId?.toString() === user.id;
  },
  'admin:view': (user) => {
    return (ROLE_HIERARCHY[user.role] ?? 0) >= ROLE_HIERARCHY['Admin'];
  },
};

const checkPolicy = (user, action, resource = {}) => {
  const policy = POLICIES[action];
  if (!policy) return false;
  return policy(user, resource);
};

module.exports = { checkPolicy, POLICIES };
