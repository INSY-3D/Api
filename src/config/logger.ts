import winston from 'winston';
import path from 'path';

// Task 2 Compliant: Comprehensive logging for audit and monitoring
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    return JSON.stringify({
      timestamp,
      level,
      message,
      ...meta
    });
  })
);

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');

// Configure transports
const transports: winston.transport[] = [
  // Console transport for development
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  })
];

// File transport for production
if (process.env.NODE_ENV === 'production') {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      format: logFormat,
      maxsize: 20 * 1024 * 1024, // 20MB
      maxFiles: 5
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      format: logFormat,
      maxsize: 20 * 1024 * 1024, // 20MB
      maxFiles: 5
    })
  );
}

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: {
    service: 'nexuspay-api',
    version: process.env.npm_package_version || '1.0.0'
  },
  transports,
  exitOnError: false
});

// Security event logger (separate for audit purposes)
export const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'nexuspay-security',
    type: 'security-event'
  },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'security.log'),
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 10
    })
  ]
});

// Audit logger for immutable audit trail
export const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'nexuspay-audit',
    type: 'audit-entry'
  },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      maxsize: 100 * 1024 * 1024, // 100MB
      maxFiles: 20
    })
  ]
});

// Performance logger
export const performanceLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'nexuspay-performance',
    type: 'performance-metric'
  },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'performance.log'),
      maxsize: 30 * 1024 * 1024, // 30MB
      maxFiles: 5
    })
  ]
});

// Log uncaught exceptions
logger.exceptions.handle(
  new winston.transports.File({
    filename: path.join(logsDir, 'exceptions.log')
  })
);

// Log unhandled promise rejections
logger.rejections.handle(
  new winston.transports.File({
    filename: path.join(logsDir, 'rejections.log')
  })
);

// Helper functions for structured logging
export const logSecurityEvent = (eventType: string, description: string, metadata?: any) => {
  securityLogger.info('Security Event', {
    eventType,
    description,
    timestamp: new Date().toISOString(),
    ...metadata
  });
};

export const logAuditEvent = (eventType: string, userId: string, description: string, metadata?: any) => {
  auditLogger.info('Audit Event', {
    eventType,
    userId,
    description,
    timestamp: new Date().toISOString(),
    ...metadata
  });
};

export const logPerformanceMetric = (endpoint: string, method: string, responseTime: number, statusCode: number) => {
  performanceLogger.info('Performance Metric', {
    endpoint,
    method,
    responseTime,
    statusCode,
    timestamp: new Date().toISOString()
  });
};
