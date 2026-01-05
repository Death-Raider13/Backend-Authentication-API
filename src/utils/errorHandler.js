/**
 * Comprehensive Error Handling Utilities
 * Provides standardized error handling across the application
 */

/**
 * Custom error classes for different types of application errors
 */
class AppError extends Error {
  constructor(message, statusCode, code = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, 400, 'VALIDATION_ERROR');
    this.details = details;
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409, 'CONFLICT_ERROR');
  }
}

class RateLimitError extends AppError {
  constructor(message = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_ERROR');
  }
}

class DatabaseError extends AppError {
  constructor(message = 'Database operation failed') {
    super(message, 500, 'DATABASE_ERROR');
  }
}

/**
 * Error response formatter
 * Creates consistent error response structure
 */
const formatErrorResponse = (error, requestId = null, includeStack = false) => {
  const response = {
    success: false,
    error: {
      code: error.code || 'INTERNAL_ERROR',
      message: error.message || 'An unexpected error occurred',
      ...(error.details && { details: error.details }),
      ...(requestId && { requestId })
    },
    timestamp: new Date().toISOString()
  };

  if (includeStack && error.stack) {
    response.error.stack = error.stack;
  }

  return response;
};

/**
 * Error logger
 * Logs errors with appropriate context and severity
 */
const logError = (error, req = null, severity = 'error') => {
  const logData = {
    message: error.message,
    code: error.code,
    statusCode: error.statusCode,
    stack: error.stack,
    timestamp: new Date().toISOString(),
    severity
  };

  if (req) {
    logData.request = {
      id: req.requestId,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id
    };
  }

  if (severity === 'error' || error.statusCode >= 500) {
    console.error('Application Error:', logData);
  } else {
    console.warn('Application Warning:', logData);
  }
};

/**
 * Mongoose error handler
 * Converts Mongoose errors to application errors
 */
const handleMongooseError = (error) => {
  if (error.name === 'ValidationError') {
    const details = Object.values(error.errors).map(err => ({
      field: err.path,
      message: err.message,
      value: err.value
    }));
    return new ValidationError('Validation failed', details);
  }

  if (error.name === 'CastError') {
    return new ValidationError(`Invalid ${error.path}: ${error.value}`);
  }

  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    const value = error.keyValue[field];
    return new ConflictError(`${field} '${value}' already exists`);
  }

  if (error.name === 'MongoNetworkError' || error.name === 'MongoTimeoutError') {
    return new DatabaseError('Database connection failed');
  }

  return new DatabaseError(error.message);
};

/**
 * JWT error handler
 * Converts JWT errors to application errors
 */
const handleJWTError = (error) => {
  if (error.name === 'JsonWebTokenError') {
    return new AuthenticationError('Invalid token');
  }

  if (error.name === 'TokenExpiredError') {
    return new AuthenticationError('Token expired');
  }

  if (error.name === 'NotBeforeError') {
    return new AuthenticationError('Token not active');
  }

  return new AuthenticationError('Token validation failed');
};

/**
 * HTTP status code mapper
 * Maps error types to appropriate HTTP status codes
 */
const getStatusCode = (error) => {
  if (error.statusCode) {
    return error.statusCode;
  }

  // Map common error types
  const errorTypeMap = {
    'ValidationError': 400,
    'CastError': 400,
    'JsonWebTokenError': 401,
    'TokenExpiredError': 401,
    'UnauthorizedError': 401,
    'ForbiddenError': 403,
    'NotFoundError': 404,
    'ConflictError': 409,
    'RateLimitError': 429,
    'MongoError': 500,
    'MongoNetworkError': 500,
    'MongoTimeoutError': 500
  };

  return errorTypeMap[error.name] || 500;
};

module.exports = {
  // Error classes
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  
  // Utility functions
  formatErrorResponse,
  logError,
  handleMongooseError,
  handleJWTError,
  getStatusCode
};