/**
 * Middleware exports
 * Central export point for all middleware components
 */

const auth = require('./auth');
const rateLimiter = require('./rateLimiter');
const validation = require('./validation');
const auditLogger = require('./auditLogger');
const security = require('./security');
const errorHandler = require('./errorHandler');

module.exports = {
  // Authentication middleware
  auth,
  
  // Rate limiting middleware
  rateLimiter,
  
  // Validation middleware
  validation,
  
  // Audit logging middleware
  auditLogger,
  
  // Security middleware
  security,
  
  // Error handling middleware
  errorHandler
};