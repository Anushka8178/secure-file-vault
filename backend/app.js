const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');

const env = require('./config/env');
const logger = require('./shared/logger');
const { error: errorResponse } = require('./shared/response');
const { AppError } = require('./shared/errors');
const { generateCsrfToken, validateCsrf } = require('./auth/middleware/csrf');
const { ipLimiter } = require('./auth/middleware/rateLimiter');

// Route modules
const authRoutes = require('./auth/routes/auth.routes');
const adminRoutes = require('./admin/admin.routes');
const linkRoutes = require('./links/signedLink.routes');

const app = express();

// ── Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// ── CORS
app.use(cors({
  origin: env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
}));

// ── Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ── Logging
app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));

// ── Trust proxy (for correct IP behind nginx)
app.set('trust proxy', 1);

// ── Global rate limiter
app.use(ipLimiter);

// ── CSRF
app.use(generateCsrfToken);
app.use(validateCsrf);

// ── Routes
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
app.use('/links', linkRoutes);

// ── JWKS well-known endpoint (also mounted in auth routes)
app.get('/.well-known/jwks.json', (req, res) => {
  const { getJwks } = require('./auth/services/jwt.service');
  res.json(getJwks());
});

// ── Health check
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ── 404
app.use((req, res) => {
  errorResponse(res, 'Route not found', 404, 'NOT_FOUND');
});

// ── Global error handler
app.use((err, req, res, next) => {
  if (err.isOperational) {
    const details = err.details || undefined;
    return errorResponse(res, err.message, err.statusCode, err.code, details);
  }
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  errorResponse(res, 'Internal server error', 500, 'INTERNAL_ERROR');
});

module.exports = app;
