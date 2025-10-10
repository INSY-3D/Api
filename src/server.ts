import express from 'express';
import cors from 'cors';
import compression from 'compression';
import https from 'https';
import http from 'http';
import fs from 'fs';
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

      // Check for SSL/TLS certificates (Task 2 Requirement)
      const useHttps = this.shouldUseHttps();

      if (useHttps) {
        const httpsOptions = this.getHttpsOptions();
        
        // Create HTTPS server
        const httpsServer = https.createServer(httpsOptions, this.app);
        
        httpsServer.listen(this.port, config.server.host, () => {
          logger.info('NexusPay API Server started with TLS 1.3', {
            protocol: 'HTTPS',
            port: this.port,
            host: config.server.host,
            environment: config.server.nodeEnv,
            version: process.env.npm_package_version || '1.0.0',
            tlsVersion: config.tls?.minVersion || 'TLSv1.3',
          });

          logger.info('Secure server endpoints', {
            localUrl: `https://${config.server.host}:${this.port}`,
            apiUrl: `https://${config.server.host}:${this.port}/api/v1`,
            healthUrl: `https://${config.server.host}:${this.port}/health`,
          });
        });

        // Optional: Start HTTP server that redirects to HTTPS
        if (config.server.isProduction) {
          const httpPort = 80;
          const httpApp = express();
          
          // Redirect all HTTP to HTTPS
          httpApp.use((req, res) => {
            res.redirect(301, `https://${req.headers.host}${req.url}`);
          });

          httpApp.listen(httpPort, () => {
            logger.info('HTTP redirect server started', {
              port: httpPort,
              redirectTo: `https://${config.server.host}:${this.port}`,
            });
          });
        }
      } else {
        // Start HTTP server (development mode without certificates)
        this.app.listen(this.port, config.server.host, () => {
          logger.warn('Server starting without TLS/SSL - HTTP ONLY', {
            protocol: 'HTTP',
            port: this.port,
            host: config.server.host,
            environment: config.server.nodeEnv,
            version: process.env.npm_package_version || '1.0.0',
          });

          if (config.server.isDevelopment) {
            logger.warn('⚠️  For production, configure SSL/TLS certificates', {
              guide: 'See SSL_SETUP_GUIDE.md for instructions',
            });
            
            logger.info('Development server information', {
              localUrl: `http://${config.server.host}:${this.port}`,
              apiUrl: `http://${config.server.host}:${this.port}/api/v1`,
              healthUrl: `http://${config.server.host}:${this.port}/health`,
            });
          }
        });
      }
    } catch (error) {
      logger.error('Failed to start server', { error });
      process.exit(1);
    }
  }

  /**
   * Check if HTTPS should be enabled based on certificate availability
   */
  private shouldUseHttps(): boolean {
    const certPath = config.tls?.certPath || process.env.TLS_CERT_PATH;
    const keyPath = config.tls?.keyPath || process.env.TLS_KEY_PATH;

    if (!certPath || !keyPath) {
      return false;
    }

    try {
      const certExists = fs.existsSync(certPath);
      const keyExists = fs.existsSync(keyPath);

      if (certExists && keyExists) {
        logger.info('SSL/TLS certificates found', {
          certPath,
          keyPath,
        });
        return true;
      } else {
        logger.warn('SSL/TLS certificate paths configured but files not found', {
          certPath: certExists ? 'found' : 'missing',
          keyPath: keyExists ? 'found' : 'missing',
        });
        return false;
      }
    } catch (error) {
      logger.error('Error checking SSL/TLS certificates', { error });
      return false;
    }
  }

  /**
   * Get HTTPS server options with TLS 1.3 configuration
   */
  private getHttpsOptions(): https.ServerOptions {
    const certPath = config.tls?.certPath || process.env.TLS_CERT_PATH!;
    const keyPath = config.tls?.keyPath || process.env.TLS_KEY_PATH!;
    const caPath = config.tls?.caPath || process.env.TLS_CA_PATH;

    try {
      const options: https.ServerOptions = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        
        // TLS 1.3 only (Task 2 Requirement)
        minVersion: 'TLSv1.3' as any,
        maxVersion: 'TLSv1.3' as any,
        
        // Strong cipher suites for TLS 1.3
        ciphers: config.tls?.cipherSuites || [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_128_GCM_SHA256',
        ].join(':'),
        
        // Honor cipher order
        honorCipherOrder: true,
        
        // Request client certificate (optional for mTLS)
        requestCert: false,
        rejectUnauthorized: false,
      };

      // Add CA certificate if provided
      if (caPath && fs.existsSync(caPath)) {
        options.ca = fs.readFileSync(caPath);
      }

      return options;
    } catch (error) {
      logger.error('Error loading SSL/TLS certificates', { error });
      throw error;
    }
  }

  public getApp(): express.Application {
    return this.app;
  }
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
