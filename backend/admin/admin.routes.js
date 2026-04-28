const express = require('express');
const router = express.Router();
const { requireAdmin, requireSuperAdmin } = require('./admin.middleware');
const { listUsers, updateUserRole, toggleUserActive, getAuditLogs, getStats } = require('./admin.controller');
const { auditStream } = require('../audit/auditStream.sse');

router.get('/stats', requireAdmin, getStats);
router.get('/users', requireAdmin, listUsers);
router.patch('/users/:id/role', requireSuperAdmin, updateUserRole);
router.patch('/users/:id/toggle-active', requireAdmin, toggleUserActive);
router.get('/audit', requireAdmin, getAuditLogs);
router.get('/audit/stream', ...auditStream);

module.exports = router;
