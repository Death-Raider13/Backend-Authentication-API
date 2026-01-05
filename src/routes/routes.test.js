const request = require('supertest');
const app = require('../app');

describe('API Routes Integration', () => {
  describe('Route Mounting', () => {
    test('API root endpoint should return service information', async () => {
      const response = await request(app)
        .get('/api')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.service).toBe('Backend Authentication Service');
      expect(response.body.data.endpoints).toHaveProperty('authentication');
      expect(response.body.data.endpoints).toHaveProperty('otp');
      expect(response.body.data.endpoints).toHaveProperty('password');
    });

    test('Authentication routes should be accessible', async () => {
      // Test signup route exists (will fail validation but route should be found)
      const response = await request(app)
        .post('/api/auth/signup')
        .send({})
        .expect(400); // Validation error, not 404

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('OTP routes should be accessible', async () => {
      // Test request-otp route exists (will fail validation but route should be found)
      const response = await request(app)
        .post('/api/auth/request-otp')
        .send({})
        .expect(400); // Validation error, not 404

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('Password routes should be accessible', async () => {
      // Test forgot-password route exists (will fail validation but route should be found)
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({})
        .expect(400); // Validation error, not 404

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('Protected routes should require authentication', async () => {
      // Test profile route requires authentication
      const response = await request(app)
        .get('/api/auth/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('MISSING_TOKEN');
    });

    test('Non-existent auth routes should return 404', async () => {
      const response = await request(app)
        .get('/api/auth/non-existent')
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('Rate Limiting', () => {
    test('Routes should have rate limiting headers', async () => {
      const response = await request(app)
        .get('/api')
        .expect(200);

      // Check for rate limiting headers
      expect(response.headers).toHaveProperty('ratelimit-limit');
      expect(response.headers).toHaveProperty('ratelimit-remaining');
      expect(response.headers).toHaveProperty('ratelimit-reset');
    });
  });

  describe('Error Handling', () => {
    test('Routes should return consistent error format', async () => {
      const response = await request(app)
        .post('/api/auth/signup')
        .send({})
        .expect(400);

      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body).toHaveProperty('timestamp');
    });
  });
});