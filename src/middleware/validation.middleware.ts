import { Request, Response, NextFunction } from 'express';
import { z, ZodSchema } from 'zod';
import { logger } from '@/config/logger';

// Task 2 Compliant: Request validation middleware
export const validateRequest = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // Validate request body
      const validatedData = schema.parse(req.body);
      
      // Replace request body with validated data
      req.body = validatedData;
      
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          value: (err as any).input,
        }));

        logger.warn('Request validation failed', {
          errors,
          path: req.path,
          method: req.method,
          ip: req.ip,
        });

        res.status(400).json({
          success: false,
          message: 'Validation failed',
          code: 'VALIDATION_FAILED',
          errors: errors.map(err => err.message),
        });
        return;
      }

      logger.error('Validation middleware error', { error });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        code: 'INTERNAL_ERROR',
      });
    }
  };
};

// Validate query parameters
export const validateQuery = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const validatedData = schema.parse(req.query);
      req.query = validatedData;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          value: (err as any).input,
        }));

        logger.warn('Query validation failed', {
          errors,
          path: req.path,
          method: req.method,
          ip: req.ip,
        });

        res.status(400).json({
          success: false,
          message: 'Query validation failed',
          code: 'QUERY_VALIDATION_FAILED',
          errors: errors.map(err => err.message),
        });
        return;
      }

      logger.error('Query validation middleware error', { error });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        code: 'INTERNAL_ERROR',
      });
    }
  };
};

// Validate path parameters
export const validateParams = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const validatedData = schema.parse(req.params);
      req.params = validatedData;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          value: (err as any).input,
        }));

        logger.warn('Params validation failed', {
          errors,
          path: req.path,
          method: req.method,
          ip: req.ip,
        });

        res.status(400).json({
          success: false,
          message: 'Path parameter validation failed',
          code: 'PARAMS_VALIDATION_FAILED',
          errors: errors.map(err => err.message),
        });
        return;
      }

      logger.error('Params validation middleware error', { error });
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        code: 'INTERNAL_ERROR',
      });
    }
  };
};

// Sanitize request body
export const sanitizeRequest = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeObject(req.body);
    }
    next();
  } catch (error) {
    logger.error('Request sanitization error', { error });
    next(); // Continue even if sanitization fails
  }
};

// Helper function to sanitize objects recursively
function sanitizeObject(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }

  const sanitized: any = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      // Remove null bytes and control characters
      sanitized[key] = value.replace(/[\x00-\x1F\x7F]/g, '').trim();
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}
