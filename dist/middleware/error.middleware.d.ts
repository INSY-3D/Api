import { Request, Response, NextFunction } from 'express';
export interface ApiError extends Error {
    statusCode?: number;
    code?: string;
    details?: any;
}
export declare const errorHandler: (error: ApiError, req: Request, res: Response, next: NextFunction) => void;
export declare const notFoundHandler: (req: Request, res: Response, next: NextFunction) => void;
export declare class ValidationError extends Error {
    statusCode: number;
    code: string;
    details: any;
    constructor(message: string, details?: any);
}
export declare class AuthenticationError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class AuthorizationError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class NotFoundError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class ConflictError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class RateLimitError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class DatabaseError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare class ExternalServiceError extends Error {
    statusCode: number;
    code: string;
    constructor(message?: string);
}
export declare const asyncHandler: (fn: Function) => (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=error.middleware.d.ts.map