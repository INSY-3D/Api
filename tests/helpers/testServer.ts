import { Application } from 'express';
import { NexusPayServer } from '@/server';
import request from 'supertest';

let testServer: NexusPayServer | null = null;
let testApp: Application | null = null;

/**
 * Get or create a test server instance
 */
export function getTestServer(): { server: NexusPayServer; app: Application } {
  if (!testServer) {
    testServer = new NexusPayServer();
    testApp = testServer.getApp();
  }
  return { server: testServer, app: testApp! };
}

/**
 * Get a supertest request instance for testing
 */
export function getTestRequest() {
  const { app } = getTestServer();
  return request(app);
}

/**
 * Reset the test server (useful for tests that need a fresh instance)
 */
export function resetTestServer(): void {
  testServer = null;
  testApp = null;
}
