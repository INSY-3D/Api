import winston from 'winston';
export declare const logger: winston.Logger;
export declare const securityLogger: winston.Logger;
export declare const auditLogger: winston.Logger;
export declare const performanceLogger: winston.Logger;
export declare const logSecurityEvent: (eventType: string, description: string, metadata?: any) => void;
export declare const logAuditEvent: (eventType: string, userId: string, description: string, metadata?: any) => void;
export declare const logPerformanceMetric: (endpoint: string, method: string, responseTime: number, statusCode: number) => void;
//# sourceMappingURL=logger.d.ts.map