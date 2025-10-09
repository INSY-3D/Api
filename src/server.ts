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
  corsOptions 
} from '@/middleware/security.middleware';
import { errorHandler } from '@/middleware/error.middleware';
import { notFoundHandler } from '@/middleware/notFound.middleware';

// Import routes
import authRoutes from '@/routes/auth.routes';
import paymentRoutes from '@/routes/payment.routes';
import beneficiaryRoutes from '@/routes/beneficiary.routes';

// Task 2 Compliant: Express server with security middleware
class NexusPayServer {
  private app: express.Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = config.server.port;
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  private setupMiddleware(): void {
    // Security headers (Task 2 Requirement: TLS 1.3, security headers)
    this.app.use(securityHeaders);

    // CORS configuration
    this.app.use(cors(corsOptions));

    // Compression middleware
    this.app.use(compression());

    // Request logging
    this.app.use(requestLogging);

    // WAF middleware (Task 2 Requirement: Attack protections)
    this.app.use(wafMiddleware);

    // Rate limiting
    this.app.use(apiRateLimit);

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Trust proxy for accurate IP addresses
    this.app.set('trust proxy', 1);
  }

  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        success: true,
        message: 'NexusPay API is healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: config.server.nodeEnv,
      });
    });

    // API routes
    this.app.use('/api/v1/auth', authRoutes);
    this.app.use('/api/v1/payments', paymentRoutes);
    this.app.use('/api/v1/beneficiaries', beneficiaryRoutes);

    // Root endpoint
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
    // 404 handler
    this.app.use(notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);
  }

  public async start(): Promise<void> {
  try {
    // Connect to database
    await connectDatabase();

    // Use Render's injected PORT or default to 10000 locally
    const PORT = process.env.PORT ? Number(process.env.PORT) : this.port;

    // Start server — omit host so it binds to 0.0.0.0 automatically
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


// Create and start server
const server = new NexusPayServer();

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise });
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
server.start().catch((error) => {
  logger.error('Server startup failed', { error });
  process.exit(1);
});

export default server;
