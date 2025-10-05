"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.gracefulShutdown = exports.checkDatabaseHealth = exports.disconnectDatabase = exports.connectDatabase = exports.prisma = void 0;
const client_1 = require("@prisma/client");
const logger_1 = require("./logger");
exports.prisma = new client_1.PrismaClient({
    log: [
        {
            emit: 'event',
            level: 'query',
        },
        {
            emit: 'event',
            level: 'error',
        },
        {
            emit: 'event',
            level: 'info',
        },
        {
            emit: 'event',
            level: 'warn',
        },
    ],
});
if (process.env.NODE_ENV === 'development') {
    exports.prisma.$on('query', (e) => {
        logger_1.logger.debug('Database Query', {
            query: e.query,
            params: e.params,
            duration: `${e.duration}ms`,
        });
    });
}
exports.prisma.$on('error', (e) => {
    logger_1.logger.error('Database Error', {
        error: e.message,
        target: e.target,
    });
});
exports.prisma.$on('info', (e) => {
    logger_1.logger.info('Database Info', {
        message: e.message,
        target: e.target,
    });
});
exports.prisma.$on('warn', (e) => {
    logger_1.logger.warn('Database Warning', {
        message: e.message,
        target: e.target,
    });
});
const connectDatabase = async () => {
    try {
        await exports.prisma.$connect();
        logger_1.logger.info('Database connected successfully');
    }
    catch (error) {
        logger_1.logger.error('Failed to connect to database', { error });
        throw error;
    }
};
exports.connectDatabase = connectDatabase;
const disconnectDatabase = async () => {
    try {
        await exports.prisma.$disconnect();
        logger_1.logger.info('Database disconnected successfully');
    }
    catch (error) {
        logger_1.logger.error('Failed to disconnect from database', { error });
        throw error;
    }
};
exports.disconnectDatabase = disconnectDatabase;
const checkDatabaseHealth = async () => {
    try {
        await exports.prisma.$queryRaw `SELECT 1`;
        return true;
    }
    catch (error) {
        logger_1.logger.error('Database health check failed', { error });
        return false;
    }
};
exports.checkDatabaseHealth = checkDatabaseHealth;
const gracefulShutdown = async () => {
    logger_1.logger.info('Starting graceful shutdown...');
    try {
        await (0, exports.disconnectDatabase)();
        logger_1.logger.info('Graceful shutdown completed');
    }
    catch (error) {
        logger_1.logger.error('Error during graceful shutdown', { error });
        process.exit(1);
    }
};
exports.gracefulShutdown = gracefulShutdown;
process.on('SIGINT', exports.gracefulShutdown);
process.on('SIGTERM', exports.gracefulShutdown);
process.on('SIGUSR2', exports.gracefulShutdown);
//# sourceMappingURL=database.js.map