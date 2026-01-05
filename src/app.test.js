const request = require('supertest');
const app = require('./app');

describe('Basic App Setup', () => {
  test('Health check endpoint should return 200', async () => {
    const response = await request(app)
      .get('/health')
      .expect(200);

    expect(response.body).toHaveProperty('success', true);
    expect(response.body).toHaveProperty('message', 'Backend Authentication Service is running');
    expect(response.body).toHaveProperty('timestamp');
    expect(response.body).toHaveProperty('environment', 'test');
  });

  test('Non-existent route should return 404', async () => {
    const response = await request(app)
      .get('/non-existent-route')
      .expect(404);

    expect(response.body).toHaveProperty('success', false);
    expect(response.body.error).toHaveProperty('code', 'NOT_FOUND');
  });
});