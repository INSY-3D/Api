import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types';
export declare const authenticateToken: (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void>;
export declare const requireRole: (roles: string[]) => (req: AuthenticatedRequest, res: Response, next: NextFunction) => void;
export declare const requireCustomer: (req: AuthenticatedRequest, res: Response, next: NextFunction) => void;
export declare const requireStaff: (req: AuthenticatedRequest, res: Response, next: NextFunction) => void;
export declare const requireAdmin: (req: AuthenticatedRequest, res: Response, next: NextFunction) => void;
export declare const optionalAuth: (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void>;
export declare const validateSession: (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void>;
export declare const validateDevice: (req: AuthenticatedRequest, res: Response, next: NextFunction) => Promise<void>;
export declare const authRateLimit: (req: Request, res: Response, next: NextFunction) => void;
export declare const csrfProtection: (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=auth.middleware.d.ts.map