import express from 'express';
import cors from 'cors';
import compression from 'compression';
import { config } from '@/config';
import { logger } from '@/config/logger';
import { connectDatabase } from '@/config/database';
import {
  securityHeaders,
  requestLogging,
  wafMiddleware,
  apiRateLimit,
  corsOptions,
} from '@/middleware/security.middleware';
import { errorHandler } from '@/middleware/error.middleware';
import { notFoundHandler } from '@/middleware/notFound.middleware';

// Import routes
import authRoutes from '@/routes/auth.routes';
import paymentRoutes from '@/routes/payment.routes';
import beneficiaryRoutes from '@/routes/beneficiary.routes';

// ------------------------------
// NexusPayServer Class
// ------------------------------
class NexusPayServer {
  private app: express.Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = Number(process.env.PORT) || config.server.port || 10000;
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  private setupMiddleware(): void {
    this.app.use(securityHeaders);
    this.app.use(cors(corsOptions));
    this.app.use(compression());
    this.app.use(requestLogging);
    this.app.use(wafMiddleware);
    this.app.use(apiRateLimit);
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    this.app.set('trust proxy', 1);
  }

  private setupRoutes(): void {
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        success: true,
        message: 'NexusPay API is healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: config.server.nodeEnv,
      });
    });

    this.app.use('/api/v1/auth', authRoutes);
    this.app.use('/api/v1/payments', paymentRoutes);
    this.app.use('/api/v1/beneficiaries', beneficiaryRoutes);

    this.app.get('/', (req, res) => {
      res.status(200).json({
        success: true,
        message: 'NexusPay API - Task 2 Compliant',
        version: process.env.npm_package_version || '1.0.0',
        environment: config.server.nodeEnv,
        endpoints: {
          auth: '/api/v1/auth',
          payments: '/api/v1/payments',
          health: '/health',
        },
      });
    });
  }

  private setupErrorHandling(): void {
    this.app.use(notFoundHandler);
    this.app.use(errorHandler);
  }

  public async start(): Promise<void> {
    try {
      await connectDatabase();
      const PORT = process.env.PORT ? Number(process.env.PORT) : this.port;

      this.app.listen(PORT, () => {
        logger.info(`NexusPay API Server started on port ${PORT}`, {
          environment: config.server.nodeEnv,
          version: process.env.npm_package_version || '1.0.0',
        });

        if (config.server.isDevelopment) {
          logger.info('Development server information', {
            localUrl: `http://localhost:${PORT}`,
            apiUrl: `http://localhost:${PORT}/api/v1`,
            healthUrl: `http://localhost:${PORT}/health`,
          });
        }
      });
    } catch (error) {
      logger.error('Failed to start server', { error });
      process.exit(1);
    }
  }

  public getApp(): express.Application {
    return this.app;
  }
}

// ------------------------------
// Global Handlers & Startup
// ------------------------------
const server = new NexusPayServer();

process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', { error });
  process.exit(1);
});

process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
  logger.error('Unhandled Rejection', { reason, promise });
  process.exit(1);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

server.start().catch((error) => {
  logger.error('Server startup failed', { error });
  process.exit(1);
});

export default server;
