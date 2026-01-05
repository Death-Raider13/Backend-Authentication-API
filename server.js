#!/usr/bin/env node

/**
 * Main application entry point for the Backend Authentication Service
 * Handles server startup, database connection, and graceful shutdown
 */

const app = require('./src/app');
const { connectDB } = require('./src/config');
const { config } = require('./src/config/env');
const { 
  unhandledRejectionHandler, 
  uncaughtExceptionHandler 
} = require('./src/middleware/errorHandler');

// Global error handlers for uncaught exceptions
process.on('uncaughtException', uncaughtExceptionHandler);
process.on('unhandledRejection', unhandledRejectionHandler);

let server;

/**
 * Start the server with proper error handling and database connection
 */
const startServer = async () => {
  try {
    console.log('Starting Backend Authentication Service...');
    console.log(`Environment: ${config.nodeEnv}`);
    console.log(`Port: ${config.port}`);
    
    // Connect to database first
    console.log('Connecting to database...');
    await connectDB();
    console.log('Database connected successfully');
    
    // Start HTTP server
    server = app.listen(config.port, () => {
      console.log(`✅ Authentication service running on port ${config.port}`);
      console.log(`🌍 Environment: ${config.nodeEnv}`);
      console.log(`📊 Health check available at: http://localhost:${config.port}/health`);
      console.log(`🔐 API endpoints available at: http://localhost:${config.port}/api`);
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.syscall !== 'listen') {
        throw error;
      }

      const bind = typeof config.port === 'string'
        ? 'Pipe ' + config.port
        : 'Port ' + config.port;

      switch (error.code) {
        case 'EACCES':
          console.error(`${bind} requires elevated privileges`);
          process.exit(1);
          break;
        case 'EADDRINUSE':
          console.error(`${bind} is already in use`);
          process.exit(1);
          break;
        default:
          throw error;
      }
    });

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

/**
 * Graceful shutdown handler
 */
const gracefulShutdown = (signal) => {
  console.log(`\n📡 Received ${signal}. Starting graceful shutdown...`);
  
  if (server) {
    server.close((err) => {
      if (err) {
        console.error('Error during server shutdown:', err);
        process.exit(1);
      }
      
      console.log('✅ HTTP server closed');
      
      // Close database connection
      const mongoose = require('mongoose');
      mongoose.connection.close(() => {
        console.log('✅ Database connection closed');
        console.log('👋 Graceful shutdown completed');
        process.exit(0);
      });
    });

    // Force shutdown after 10 seconds
    setTimeout(() => {
      console.error('⚠️  Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
};

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start the server only if not in test environment
if (process.env.NODE_ENV !== 'test') {
  startServer();
}

module.exports = { server, startServer, gracefulShutdown };