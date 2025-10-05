import { Request, Response, NextFunction } from 'express';
import { authService } from '@/services/auth.service';
import { logger, logSecurityEvent } from '@/config/logger';
import { AuthenticatedRequest } from '@/types';
import { EventType, SecurityRiskLevel } from '@/types/enums';

// Task 2 Compliant: JWT authentication middleware
export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access token required',
        code: 'MISSING_TOKEN',
      });
      return;
    }

    // Verify JWT token
    const payload = authService.verifyAccessToken(token);
    if (!payload) {
      res.status(401).json({
        success: false,
        message: 'Invalid or expired token',
        code: 'INVALID_TOKEN',
      });
      return;
    }

    // Get user from database
    const user = await authService.getUserById(payload.userId);
    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'User not found or inactive',
        code: 'USER_NOT_FOUND',
      });
      return;
    }

    // Get user session
    const session = await authService.getUserSession(payload.sessionId);
    if (!session || !session.isActive || session.expiresAt < new Date()) {
      res.status(401).json({
        success: false,
        message: 'Session expired or invalid',
        code: 'SESSION_EXPIRED',
      });
      return;
    }

    // Attach user and session to request
    req.user = user;
    req.session = session;

    next();
  } catch (error) {
    logger.error('Authentication middleware error', { error });
    res.status(500).json({
      success: false,
      message: 'Authentication error',
      code: 'AUTH_ERROR',
    });
  }
};

// Role-based authorization middleware
export const requireRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      logSecurityEvent(EventType.SECURITY_VIOLATION, 
        `Unauthorized access attempt by user ${req.user.id} to role-protected resource`, {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: roles,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        riskLevel: SecurityRiskLevel.HIGH,
      });

      res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
      });
      return;
    }

    next();
  };
};

// Customer-only access
export const requireCustomer = requireRole(['customer']);

// Staff-only access
export const requireStaff = requireRole(['staff', 'admin']);

// Admin-only access
export const requireAdmin = requireRole(['admin']);

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      next();
      return;
    }

    // Verify JWT token
    const payload = authService.verifyAccessToken(token);
    if (!payload) {
      next();
      return;
    }

    // Get user from database
    const user = await authService.getUserById(payload.userId);
    if (!user || !user.isActive) {
      next();
      return;
    }

    // Get user session
    const session = await authService.getUserSession(payload.sessionId);
    if (!session || !session.isActive || session.expiresAt < new Date()) {
      next();
      return;
    }

    // Attach user and session to request
    req.user = user;
    req.session = session;

    next();
  } catch (error) {
    logger.error('Optional authentication middleware error', { error });
    next(); // Continue even if there's an error
  }
};

// Session validation middleware
export const validateSession = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.session) {
      res.status(401).json({
        success: false,
        message: 'Valid session required',
        code: 'SESSION_REQUIRED',
      });
      return;
    }

    // Check if session is still valid
    if (req.session.expiresAt < new Date()) {
      // Deactivate expired session
      await authService.logout(req.user!.id, req.session.id);
      
      res.status(401).json({
        success: false,
        message: 'Session expired',
        code: 'SESSION_EXPIRED',
      });
      return;
    }

    // Check if session is active
    if (!req.session.isActive) {
      res.status(401).json({
        success: false,
        message: 'Session invalidated',
        code: 'SESSION_INVALID',
      });
      return;
    }

    next();
  } catch (error) {
    logger.error('Session validation middleware error', { error });
    res.status(500).json({
      success: false,
      message: 'Session validation error',
      code: 'SESSION_ERROR',
    });
  }
};

// Device validation middleware
export const validateDevice = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !req.session) {
      next();
      return;
    }

    const currentIp = req.ip;
    const currentUserAgent = req.get('User-Agent');

    // Check if device changed
    if (req.session.ipAddress !== currentIp || req.session.userAgent !== currentUserAgent) {
      logSecurityEvent(EventType.SUSPICIOUS_ACTIVITY, 
        `Device change detected for user ${req.user.id}`, {
        userId: req.user.id,
        oldIp: req.session.ipAddress,
        newIp: currentIp,
        oldUserAgent: req.session.userAgent,
        newUserAgent: currentUserAgent,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });

      // Update session with new device info
      req.session.ipAddress = currentIp || null;
      req.session.userAgent = currentUserAgent || null;
    }

    next();
  } catch (error) {
    logger.error('Device validation middleware error', { error });
    next(); // Continue even if there's an error
  }
};

// Rate limiting for authentication endpoints
export const authRateLimit = (req: Request, res: Response, next: NextFunction): void => {
  // This would integrate with express-rate-limit
  // For now, we'll just pass through
  next();
};

// CSRF protection middleware
export const csrfProtection = (req: Request, res: Response, next: NextFunction): void => {
  // Skip CSRF for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }

  const csrfToken = req.headers['x-csrf-token'] as string;
  const sessionToken = (req as any).session?.csrfToken; // This would come from session

  if (!csrfToken || !sessionToken || csrfToken !== sessionToken) {
    res.status(403).json({
      success: false,
      message: 'CSRF token mismatch',
      code: 'CSRF_MISMATCH',
    });
    return;
  }

  next();
};
