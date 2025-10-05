import { Request, Response, NextFunction } from 'express';
import { logger } from '@/config/logger';
import { logSecurityEvent } from '@/config/logger';
import { EventType, SecurityRiskLevel } from '@/types/enums';

// Task 2 Compliant: Error handling middleware

export interface ApiError extends Error {
  statusCode?: number;
  code?: string;
  details?: any;
}

export const errorHandler = (
  error: ApiError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Log the error
  logger.error('API Error', {
    error: error.message,
    stack: error.stack,
    statusCode: error.statusCode || 500,
    code: error.code,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });

  // Log security events for certain error types
  if (error.statusCode === 401 || error.statusCode === 403) {
    logSecurityEvent(EventType.SECURITY_VIOLATION, `Security error: ${error.message}`, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      statusCode: error.statusCode,
      riskLevel: SecurityRiskLevel.MEDIUM,
    });
  }

  // Determine status code
  const statusCode = error.statusCode || 500;

  // Prepare error response
  const errorResponse: any = {
    success: false,
    message: error.message || 'Internal server error',
    code: error.code || 'INTERNAL_ERROR',
  };

  // Add details in development
  if (process.env.NODE_ENV === 'development') {
    errorResponse.details = error.details;
    errorResponse.stack = error.stack;
  }

  // Send error response
  res.status(statusCode).json(errorResponse);
};

export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
  const error: ApiError = new Error(`Route not found: ${req.method} ${req.path}`);
  error.statusCode = 404;
  error.code = 'ROUTE_NOT_FOUND';

  logger.warn('Route not found', {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });

  res.status(404).json({
    success: false,
    message: 'Route not found',
    code: 'ROUTE_NOT_FOUND',
  });
};

// Custom error classes
export class ValidationError extends Error {
  public statusCode = 400;
  public code = 'VALIDATION_ERROR';
  public details: any;

  constructor(message: string, details?: any) {
    super(message);
    this.name = 'ValidationError';
    this.details = details;
  }
}

export class AuthenticationError extends Error {
  public statusCode = 401;
  public code = 'AUTHENTICATION_ERROR';

  constructor(message: string = 'Authentication required') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends Error {
  public statusCode = 403;
  public code = 'AUTHORIZATION_ERROR';

  constructor(message: string = 'Insufficient permissions') {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends Error {
  public statusCode = 404;
  public code = 'NOT_FOUND';

  constructor(message: string = 'Resource not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  public statusCode = 409;
  public code = 'CONFLICT';

  constructor(message: string = 'Resource conflict') {
    super(message);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends Error {
  public statusCode = 429;
  public code = 'RATE_LIMIT_EXCEEDED';

  constructor(message: string = 'Rate limit exceeded') {
    super(message);
    this.name = 'RateLimitError';
  }
}

export class DatabaseError extends Error {
  public statusCode = 500;
  public code = 'DATABASE_ERROR';

  constructor(message: string = 'Database operation failed') {
    super(message);
    this.name = 'DatabaseError';
  }
}

export class ExternalServiceError extends Error {
  public statusCode = 502;
  public code = 'EXTERNAL_SERVICE_ERROR';

  constructor(message: string = 'External service error') {
    super(message);
    this.name = 'ExternalServiceError';
  }
}

// Async error wrapper
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
