"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logPerformanceMetric = exports.logAuditEvent = exports.logSecurityEvent = exports.performanceLogger = exports.auditLogger = exports.securityLogger = exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const path_1 = __importDefault(require("path"));
const logFormat = winston_1.default.format.combine(winston_1.default.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
}), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json(), winston_1.default.format.printf(({ timestamp, level, message, ...meta }) => {
    return JSON.stringify({
        timestamp,
        level,
        message,
        ...meta
    });
}));
const logsDir = path_1.default.join(process.cwd(), 'logs');
const transports = [
    new winston_1.default.transports.Console({
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
        format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
    })
];
if (process.env.NODE_ENV === 'production') {
    transports.push(new winston_1.default.transports.File({
        filename: path_1.default.join(logsDir, 'error.log'),
        level: 'error',
        format: logFormat,
        maxsize: 20 * 1024 * 1024,
        maxFiles: 5
    }), new winston_1.default.transports.File({
        filename: path_1.default.join(logsDir, 'combined.log'),
        format: logFormat,
        maxsize: 20 * 1024 * 1024,
        maxFiles: 5
    }));
}
exports.logger = winston_1.default.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: {
        service: 'nexuspay-api',
        version: process.env.npm_package_version || '1.0.0'
    },
    transports,
    exitOnError: false
});
exports.securityLogger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    defaultMeta: {
        service: 'nexuspay-security',
        type: 'security-event'
    },
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'security.log'),
            maxsize: 50 * 1024 * 1024,
            maxFiles: 10
        })
    ]
});
exports.auditLogger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    defaultMeta: {
        service: 'nexuspay-audit',
        type: 'audit-entry'
    },
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'audit.log'),
            maxsize: 100 * 1024 * 1024,
            maxFiles: 20
        })
    ]
});
exports.performanceLogger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    defaultMeta: {
        service: 'nexuspay-performance',
        type: 'performance-metric'
    },
    transports: [
        new winston_1.default.transports.File({
            filename: path_1.default.join(logsDir, 'performance.log'),
            maxsize: 30 * 1024 * 1024,
            maxFiles: 5
        })
    ]
});
exports.logger.exceptions.handle(new winston_1.default.transports.File({
    filename: path_1.default.join(logsDir, 'exceptions.log')
}));
exports.logger.rejections.handle(new winston_1.default.transports.File({
    filename: path_1.default.join(logsDir, 'rejections.log')
}));
const logSecurityEvent = (eventType, description, metadata) => {
    exports.securityLogger.info('Security Event', {
        eventType,
        description,
        timestamp: new Date().toISOString(),
        ...metadata
    });
};
exports.logSecurityEvent = logSecurityEvent;
const logAuditEvent = (eventType, userId, description, metadata) => {
    exports.auditLogger.info('Audit Event', {
        eventType,
        userId,
        description,
        timestamp: new Date().toISOString(),
        ...metadata
    });
};
exports.logAuditEvent = logAuditEvent;
const logPerformanceMetric = (endpoint, method, responseTime, statusCode) => {
    exports.performanceLogger.info('Performance Metric', {
        endpoint,
        method,
        responseTime,
        statusCode,
        timestamp: new Date().toISOString()
    });
};
exports.logPerformanceMetric = logPerformanceMetric;
//# sourceMappingURL=logger.js.map