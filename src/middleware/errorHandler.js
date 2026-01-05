/**
 * Comprehensive Error Handling Middleware
 * Provides centralized error handling for the entire application
 */

const { config } = require('../config/env');
const {
  formatErrorResponse,
  logError,
  handleMongooseError,
  handleJWTError,
  getStatusCode,
  AppError
} = require('../utils/errorHandler');

/**
 * Global error handling middleware
 * Catches all errors and formats them consistently
 */
const globalErrorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Handle different types of errors
  if (err.name === 'ValidationError' || err.name === 'CastError' || err.code === 11000) {
    error = handleMongooseError(err);
  } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError' || err.name === 'NotBeforeError') {
    error = handleJWTError(err);
  } else if (!err.isOperational) {
    // Convert non-operational errors to AppError
    const statusCode = getStatusCode(err);
    error = new AppError(
      config.nodeEnv === 'production' ? 'Something went wrong' : err.message,
      statusCode,
      err.code || 'INTERNAL_ERROR'
    );
  }

  // Determine if we should include stack trace
  const includeStack = config.nodeEnv !== 'production' && error.statusCode >= 500;

  // Log the error
  logError(error, req, error.statusCode >= 500 ? 'error' : 'warn');

  // Send error response
  const errorResponse = formatErrorResponse(error, req.requestId, includeStack);
  res.status(error.statusCode || 500).json(errorResponse);
};

/**
 * Async error wrapper
 * Wraps async route handlers to catch errors automatically
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * 404 Not Found handler
 * Handles requests to non-existent routes
 */
const notFoundHandler = (req, res, next) => {
  const error = new AppError(
    `Route ${req.method} ${req.originalUrl} not found`,
    404,
    'NOT_FOUND'
  );
  next(error);
};

/**
 * Validation error handler
 * Handles validation errors from middleware
 */
const validationErrorHandler = (errors, req, res, next) => {
  const error = new AppError(
    'Validation failed',
    400,
    'VALIDATION_ERROR'
  );
  error.details = errors;
  next(error);
};

/**
 * Rate limit error handler
 * Handles rate limiting errors
 */
const rateLimitErrorHandler = (req, res, next) => {
  const error = new AppError(
    'Too many requests, please try again later',
    429,
    'RATE_LIMIT_ERROR'
  );
  next(error);
};

/**
 * Database connection error handler
 * Handles database connection issues
 */
const databaseErrorHandler = (err, req, res, next) => {
  if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
    const error = new AppError(
      'Database service temporarily unavailable',
      503,
      'DATABASE_UNAVAILABLE'
    );
    next(error);
  } else {
    next(err);
  }
};

/**
 * Unhandled promise rejection handler
 * Global handler for unhandled promise rejections
 */
const unhandledRejectionHandler = (reason, promise) => {
  console.error('Unhandled Promise Rejection:', {
    reason: reason.message || reason,
    stack: reason.stack,
    promise: promise,
    timestamp: new Date().toISOString()
  });
  
  // In production, we might want to gracefully shutdown
  if (config.nodeEnv === 'production') {
    console.error('Shutting down due to unhandled promise rejection');
    process.exit(1);
  }
};

/**
 * Uncaught exception handler
 * Global handler for uncaught exceptions
 */
const uncaughtExceptionHandler = (error) => {
  console.error('Uncaught Exception:', {
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  console.error('Shutting down due to uncaught exception');
  process.exit(1);
};

module.exports = {
  globalErrorHandler,
  asyncHandler,
  notFoundHandler,
  validationErrorHandler,
  rateLimitErrorHandler,
  databaseErrorHandler,
  unhandledRejectionHandler,
  uncaughtExceptionHandler
};