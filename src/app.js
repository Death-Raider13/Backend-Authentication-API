const express = require('express');
const crypto = require('crypto');
const { config, validateEnvironment } = require('./config/env');
const { 
  helmet, 
  cors, 
  additionalSecurityHeaders,
  inputSanitizer
} = require('./middleware/security');
const { 
  globalErrorHandler, 
  notFoundHandler 
} = require('./middleware/errorHandler');

// Validate environment variables on startup
validateEnvironment();

const app = express();

// Enhanced security middleware
app.use(helmet);
app.use(require('cors')(cors));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Basic security headers and input sanitization
app.use(additionalSecurityHeaders);
app.use(inputSanitizer);

// Simplified audit logging (without response interception)
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  req.startTime = Date.now();
  next();
});

// Request/Response logging for debugging (enhanced)
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'development') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip} - ID: ${req.requestId}`);
  }
  
  // Log response when it finishes
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - req.startTime;
    if (process.env.NODE_ENV === 'development') {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms - ID: ${req.requestId}`);
    }
    originalSend.call(this, data);
  };
  
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: `${config.app.name} is running`,
    version: config.app.version,
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv
  });
});

// Mount API routes
const routes = require('./routes');
app.use('/api', routes);

// 404 handler for unmatched routes
app.use('*', notFoundHandler);

// Global error handling middleware
app.use(globalErrorHandler);

// Export the Express app for use by the server
// Server startup and database connection are handled in server.js

module.exports = app;