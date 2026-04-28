const express = require('express');
const router = express.Router();

const { register, login, refresh, logout, logoutAll, me, registerValidation, loginValidation } = require('../controllers/auth.controller');
const { setupMfa, verifyMfa, disableMfa, regenerateBackupCodes } = require('../controllers/mfa.controller');
const { forgotPassword, resetPassword, changePassword } = require('../controllers/password.controller');
const { authenticate } = require('../middleware/authenticate');
const { checkLockout } = require('../middleware/lockout');
const { authLimiter } = require('../middleware/rateLimiter');
const { getJwks } = require('../services/jwt.service');

// Public routes
router.get('/.well-known/jwks.json', (req, res) => res.json(getJwks()));
router.post('/register', authLimiter, registerValidation, register);
router.post('/login', authLimiter, checkLockout, loginValidation, login);
router.post('/refresh', refresh);
router.post('/password/forgot', authLimiter, forgotPassword);
router.post('/password/reset', authLimiter, resetPassword);

// Authenticated routes
router.use(authenticate);
router.get('/me', me);
router.post('/logout', logout);
router.post('/logout-all', logoutAll);
router.put('/password/change', changePassword);

// MFA routes
router.post('/mfa/setup', setupMfa);
router.post('/mfa/verify', verifyMfa);
router.delete('/mfa', disableMfa);
router.post('/mfa/backup-codes/regenerate', regenerateBackupCodes);

module.exports = router;
