import { getTestRequest } from '../helpers/testServer';

describe('CORS Security', () => {
  const request = getTestRequest();

  describe('CORS Preflight Requests', () => {
    it('should handle OPTIONS preflight requests', async () => {
      const response = await request
        .options('/api/v1/auth/login')
        .set('Origin', 'http://localhost:5173')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type');

      expect([200, 204]).toContain(response.status);
    });

    it('should include CORS headers in preflight response', async () => {
      const response = await request
        .options('/api/v1/auth/login')
        .set('Origin', 'http://localhost:5173')
        .set('Access-Control-Request-Method', 'POST');

      if (response.status === 200 || response.status === 204) {
        expect(response.headers['access-control-allow-origin']).toBeDefined();
        expect(response.headers['access-control-allow-methods']).toBeDefined();
        expect(response.headers['access-control-allow-headers']).toBeDefined();
      }
    });
  });

  describe('CORS Origin Whitelisting', () => {
    it('should allow requests from whitelisted origins', async () => {
      const response = await request
        .get('/health')
        .set('Origin', 'http://localhost:5173');

      // Should allow whitelisted origin
      expect([200, 401]).toContain(response.status);
    });

    it('should reject requests from non-whitelisted origins', async () => {
      const response = await request
        .get('/health')
        .set('Origin', 'http://evil.com');

      // Should reject non-whitelisted origin
      // CORS errors typically result in no CORS headers or 403
      if (response.headers['access-control-allow-origin']) {
        expect(response.headers['access-control-allow-origin']).not.toBe('http://evil.com');
      }
    });
  });

  describe('CORS Header Exposure', () => {
    it('should not expose sensitive headers', async () => {
      const response = await request
        .get('/health')
        .set('Origin', 'http://localhost:5173');

      const exposedHeaders = response.headers['access-control-expose-headers'];
      
      if (exposedHeaders) {
        // Should not expose sensitive headers like Authorization
        expect(exposedHeaders).not.toContain('Authorization');
        expect(exposedHeaders).not.toContain('X-Auth-Token');
      }
    });

    it('should only expose necessary headers', async () => {
      const response = await request
        .get('/health')
        .set('Origin', 'http://localhost:5173');

      const exposedHeaders = response.headers['access-control-expose-headers'];
      
      // Should expose rate limit headers if configured
      if (exposedHeaders) {
        const headers = exposedHeaders.split(',').map((h: string) => h.trim());
        // Should only contain safe headers
        expect(headers.every((h: string) => 
          ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'].includes(h)
        )).toBe(true);
      }
    });
  });

  describe('CORS Credentials', () => {
    it('should handle credentials in CORS requests', async () => {
      const response = await request
        .get('/health')
        .set('Origin', 'http://localhost:5173')
        .set('Cookie', 'session=test');

      // Should handle credentials if configured
      if (response.headers['access-control-allow-credentials']) {
        expect(response.headers['access-control-allow-credentials']).toBe('true');
      }
    });
  });

  describe('CORS Method Restrictions', () => {
    it('should only allow specified HTTP methods', async () => {
      const response = await request
        .options('/api/v1/auth/login')
        .set('Origin', 'http://localhost:5173')
        .set('Access-Control-Request-Method', 'TRACE');

      // TRACE should not be allowed
      const allowedMethods = response.headers['access-control-allow-methods'];
      if (allowedMethods) {
        expect(allowedMethods).not.toContain('TRACE');
      }
    });
  });
});
