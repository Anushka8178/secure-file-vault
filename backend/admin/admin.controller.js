const User = require('../auth/models/user.model');
const { queryAuditLogs } = require('../audit/audit.service');
const { auditLog } = require('../audit/audit.service');
const { success } = require('../shared/response');
const { NotFoundError } = require('../shared/errors');
const { ROLES } = require('../rbac/roles');

/**
 * GET /admin/users
 */
const listUsers = async (req, res) => {
  const { page = 1, limit = 20, role, search } = req.query;
  const filter = {};
  if (role && ROLES.includes(role)) filter.role = role;
  if (search) filter.$or = [
    { email: { $regex: search, $options: 'i' } },
    { username: { $regex: search, $options: 'i' } },
  ];

  const [users, total] = await Promise.all([
    User.find(filter).skip((page - 1) * limit).limit(Number(limit)).sort({ createdAt: -1 }),
    User.countDocuments(filter),
  ]);

  return success(res, { users, total, page: Number(page), pages: Math.ceil(total / limit) });
};

/**
 * PATCH /admin/users/:id/role
 */
const updateUserRole = async (req, res) => {
  const { role } = req.body;
  if (!ROLES.includes(role)) throw new Error('Invalid role');

  const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
  if (!user) throw new NotFoundError('User not found');

  await auditLog({ event: 'ADMIN_ROLE_CHANGE', userId: req.user.id, ip: req.ip, meta: { targetUser: req.params.id, newRole: role } });
  return success(res, { user });
};

/**
 * PATCH /admin/users/:id/toggle-active
 */
const toggleUserActive = async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) throw new NotFoundError('User not found');

  user.isActive = !user.isActive;
  await user.save();

  await auditLog({ event: user.isActive ? 'ADMIN_USER_ACTIVATED' : 'ADMIN_USER_DEACTIVATED', userId: req.user.id, ip: req.ip, meta: { targetUser: req.params.id } });
  return success(res, { user });
};

/**
 * GET /admin/audit  — paginated audit logs
 */
const getAuditLogs = async (req, res) => {
  const result = await queryAuditLogs(req.query);
  return success(res, result);
};

/**
 * GET /admin/stats
 */
const getStats = async (req, res) => {
  const [totalUsers, activeUsers, roleBreakdown] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ isActive: true }),
    User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]),
  ]);
  return success(res, { totalUsers, activeUsers, roleBreakdown });
};

module.exports = { listUsers, updateUserRole, toggleUserActive, getAuditLogs, getStats };
