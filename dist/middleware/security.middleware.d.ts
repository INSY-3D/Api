import { Request, Response, NextFunction } from 'express';
export declare const wafMiddleware: (req: Request, res: Response, next: NextFunction) => void;
export declare const createRateLimit: (options: {
    windowMs: number;
    max: number;
    message?: string;
    skipSuccessfulRequests?: boolean;
    skipFailedRequests?: boolean;
}) => import("express-rate-limit").RateLimitRequestHandler;
export declare const apiRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const loginRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const registerRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const wafRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const securityHeaders: (req: import("http").IncomingMessage, res: import("http").ServerResponse, next: (err?: unknown) => void) => void;
export declare const requestLogging: (req: Request, res: Response, next: NextFunction) => void;
export declare const ipWhitelist: (allowedIPs: string[]) => (req: Request, res: Response, next: NextFunction) => void;
export declare const requestSizeLimit: (maxSize: number) => (req: Request, res: Response, next: NextFunction) => void;
export declare const corsOptions: {
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void;
    credentials: boolean;
    methods: string[];
    allowedHeaders: string[];
    exposedHeaders: string[];
    maxAge: number;
};
//# sourceMappingURL=security.middleware.d.ts.map