const { ForbiddenError } = require('../../shared/errors');
const { ROLE_HIERARCHY } = require('../../rbac/roles');
const { checkPolicy } = require('../../rbac/abac.policy');

/**
 * RBAC: require minimum role
 * Usage: authorize('Admin') — passes if user.role >= Admin in hierarchy
 */
const authorize = (minRole) => (req, res, next) => {
  const userLevel = ROLE_HIERARCHY[req.user?.role] ?? -1;
  const requiredLevel = ROLE_HIERARCHY[minRole] ?? 999;
  if (userLevel < requiredLevel) {
    return next(new ForbiddenError(`Requires ${minRole} role or higher`));
  }
  next();
};

/**
 * Ownership check: resource must belong to the requesting user (or admin+)
 * Usage: requireOwnership('userId') — checks req.params[field] === req.user.id
 */
const requireOwnership = (paramField = 'userId') => (req, res, next) => {
  const resourceOwner = req.params[paramField] || req.resource?.userId?.toString();
  const isAdmin = (ROLE_HIERARCHY[req.user?.role] ?? -1) >= ROLE_HIERARCHY['Admin'];

  if (!isAdmin && resourceOwner !== req.user?.id) {
    return next(new ForbiddenError('You do not own this resource'));
  }
  next();
};

/**
 * ABAC: attribute-based policy check
 * Usage: checkAbac('file:download')
 */
const checkAbac = (action) => (req, res, next) => {
  const allowed = checkPolicy(req.user, action, req.resource || {});
  if (!allowed) return next(new ForbiddenError('Policy denied'));
  next();
};

module.exports = { authorize, requireOwnership, checkAbac };
