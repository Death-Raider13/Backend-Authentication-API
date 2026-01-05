// Test setup file for Jest
const { disconnectDB } = require('./database');

// Set test environment
process.env.NODE_ENV = 'test';

// Global test teardown
afterAll(async () => {
  // Close database connection after all tests
  await disconnectDB();
});