"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const compression_1 = __importDefault(require("compression"));
const config_1 = require("./config");
const logger_1 = require("./config/logger");
const database_1 = require("./config/database");
const security_middleware_1 = require("./middleware/security.middleware");
const error_middleware_1 = require("./middleware/error.middleware");
const notFound_middleware_1 = require("./middleware/notFound.middleware");
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
const payment_routes_1 = __importDefault(require("./routes/payment.routes"));
const beneficiary_routes_1 = __importDefault(require("./routes/beneficiary.routes"));
class NexusPayServer {
    app;
    port;
    constructor() {
        this.app = (0, express_1.default)();
        this.port = Number(process.env.PORT) || config_1.config.server.port || 10000;
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
    }
    setupMiddleware() {
        this.app.use(security_middleware_1.securityHeaders);
        this.app.use((0, cors_1.default)(security_middleware_1.corsOptions));
        this.app.use((0, compression_1.default)());
        this.app.use(security_middleware_1.requestLogging);
        this.app.use(security_middleware_1.wafMiddleware);
        this.app.use(security_middleware_1.apiRateLimit);
        this.app.use(express_1.default.json({ limit: '10mb' }));
        this.app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
        this.app.set('trust proxy', 1);
    }
    setupRoutes() {
        this.app.get('/health', (req, res) => {
            res.status(200).json({
                success: true,
                message: 'NexusPay API is healthy',
                timestamp: new Date().toISOString(),
                version: process.env.npm_package_version || '1.0.0',
                environment: config_1.config.server.nodeEnv,
            });
        });
        this.app.use('/api/v1/auth', auth_routes_1.default);
        this.app.use('/api/v1/payments', payment_routes_1.default);
        this.app.use('/api/v1/beneficiaries', beneficiary_routes_1.default);
        this.app.get('/', (req, res) => {
            res.status(200).json({
                success: true,
                message: 'NexusPay API - Task 2 Compliant',
                version: process.env.npm_package_version || '1.0.0',
                environment: config_1.config.server.nodeEnv,
                endpoints: {
                    auth: '/api/v1/auth',
                    payments: '/api/v1/payments',
                    health: '/health',
                },
            });
        });
    }
    setupErrorHandling() {
        this.app.use(notFound_middleware_1.notFoundHandler);
        this.app.use(error_middleware_1.errorHandler);
    }
    async start() {
        try {
            await (0, database_1.connectDatabase)();
            const PORT = process.env.PORT ? Number(process.env.PORT) : this.port;
            this.app.listen(PORT, () => {
                logger_1.logger.info(`NexusPay API Server started on port ${PORT}`, {
                    environment: config_1.config.server.nodeEnv,
                    version: process.env.npm_package_version || '1.0.0',
                });
                if (config_1.config.server.isDevelopment) {
                    logger_1.logger.info('Development server information', {
                        localUrl: `http://localhost:${PORT}`,
                        apiUrl: `http://localhost:${PORT}/api/v1`,
                        healthUrl: `http://localhost:${PORT}/health`,
                    });
                }
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to start server', { error });
            process.exit(1);
        }
    }
    getApp() {
        return this.app;
    }
}
const server = new NexusPayServer();
process.on('uncaughtException', (error) => {
    logger_1.logger.error('Uncaught Exception', { error });
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    logger_1.logger.error('Unhandled Rejection', { reason, promise });
    process.exit(1);
});
process.on('SIGTERM', () => {
    logger_1.logger.info('SIGTERM received, shutting down gracefully');
    process.exit(0);
});
process.on('SIGINT', () => {
    logger_1.logger.info('SIGINT received, shutting down gracefully');
    process.exit(0);
});
server.start().catch((error) => {
    logger_1.logger.error('Server startup failed', { error });
    process.exit(1);
});
exports.default = server;
//# sourceMappingURL=server.js.map