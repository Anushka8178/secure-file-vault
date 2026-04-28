class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
  }
}

class AuthError extends AppError {
  constructor(message = 'Authentication failed', code = 'AUTH_FAILED') {
    super(message, 401, code);
  }
}

class ForbiddenError extends AppError {
  constructor(message = 'Access denied', code = 'FORBIDDEN') {
    super(message, 403, code);
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
  }
}

class ValidationError extends AppError {
  constructor(message = 'Validation failed', details = []) {
    super(message, 422, 'VALIDATION_ERROR');
    this.details = details;
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409, 'CONFLICT');
  }
}

module.exports = { AppError, AuthError, ForbiddenError, NotFoundError, ValidationError, ConflictError };
