import { connectDatabase } from '@/config/database';
import { logger } from '@/config/logger';
import { resetTestServer } from './helpers/testServer';

beforeAll(async () => {
  // Connect to the database once before all tests
  logger.info('Connecting to test database...');
  await connectDatabase();
  logger.info('Test database connected.');
});

afterEach(() => {
  // Reset the test server instance after each test to ensure isolation
  resetTestServer();
});

afterAll(async () => {
  // Disconnect from the database after all tests are done
  // await disconnectDatabase(); // Assuming a disconnect function exists or is handled by Prisma's lifecycle
  logger.info('Test suite finished.');
});
