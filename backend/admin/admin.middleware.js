const { authenticate } = require('../auth/middleware/authenticate');
const { authorize } = require('../auth/middleware/authorize');

const requireAdmin = [authenticate, authorize('Admin')];
const requireSuperAdmin = [authenticate, authorize('SuperAdmin')];

module.exports = { requireAdmin, requireSuperAdmin };
