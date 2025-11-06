import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

export const prisma = new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'error' },
    { emit: 'event', level: 'info' },
    { emit: 'event', level: 'warn' },
  ],
});

// Log database queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query', (e: any) => {
    logger.debug('Database Query', {
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
    });
  });
}

// Log database errors/info/warn
prisma.$on('error', (e: any) => {
  logger.error('Database Error', { error: e.message, target: e.target });
});
prisma.$on('info', (e: any) => {
  logger.info('Database Info', { message: e.message, target: e.target });
});
prisma.$on('warn', (e: any) => {
  logger.warn('Database Warning', { message: e.message, target: e.target });
});

// Connection management
export const connectDatabase = async (): Promise<void> => {
  try {
    await prisma.$connect();
    logger.info('Database connected successfully');
  } catch (error) {
    logger.error('Failed to connect to database', { error });
    throw error;
  }
};

export const disconnectDatabase = async (): Promise<void> => {
  try {
    await prisma.$disconnect();
    logger.info('Database disconnected successfully');
  } catch (error) {
    logger.error('Failed to disconnect from database', { error });
    throw error;
  }
};

// Health check (MongoDB)
export const checkDatabaseHealth = async (): Promise<boolean> => {
  try {
    // Mongo: use runCommandRaw ping
    // @ts-ignore - Prisma exposes this for Mongo
    const result = await prisma.$runCommandRaw({ ping: 1 });
    // Mongo returns { ok: 1 } on success
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    return !!result?.ok;
  } catch (error) {
    logger.error('Database health check failed', { error });
    return false;
  }
};

// Graceful shutdown
export const gracefulShutdown = async (): Promise<void> => {
  logger.info('Starting graceful shutdown...');
  try {
    await disconnectDatabase();
    logger.info('Graceful shutdown completed');
  } catch (error) {
    logger.error('Error during graceful shutdown', { error });
    process.exit(1);
  }
};

// Handle process termination
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('SIGUSR2', gracefulShutdown); // nodemon
