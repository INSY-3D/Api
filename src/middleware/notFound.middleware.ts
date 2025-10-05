import { Request, Response, NextFunction } from 'express';
import { logger } from '@/config/logger';

// Task 2 Compliant: 404 Not Found middleware
export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
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
    path: req.path,
    method: req.method,
  });
};
