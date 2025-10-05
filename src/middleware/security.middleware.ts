import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { config } from '@/config';
import { logger, logSecurityEvent } from '@/config/logger';
import { EventType, SecurityRiskLevel } from '@/types/enums';
import { WafResult } from '@/types';

// Task 2 Compliant: Security middleware with WAF and rate limiting

// WAF Rules for attack detection
const WAF_RULES = [
  {
    name: 'SQL_INJECTION',
    pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)|(\b(OR|AND)\s+\d+\s*=\s*\d+)|(\b(OR|AND)\s+['"]\s*=\s*['"])/i,
    severity: 'High' as const,
    enabled: config.waf.enableSqlInjectionDetection,
  },
  {
    name: 'XSS_ATTACK',
    pattern: /<script[^>]*>.*?<\/script>|<[^>]*on\w+\s*=|javascript:|vbscript:|data:text\/html/i,
    severity: 'High' as const,
    enabled: config.waf.enableXssDetection,
  },
  {
    name: 'PATH_TRAVERSAL',
    pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c/i,
    severity: 'Medium' as const,
    enabled: config.waf.enablePathTraversalDetection,
  },
  {
    name: 'COMMAND_INJECTION',
    pattern: /[;&|`$(){}[\]\\]/,
    severity: 'High' as const,
    enabled: false, // Disabled for development
  },
  {
    name: 'LDAP_INJECTION',
    pattern: /[()=*!&|]/,
    severity: 'Medium' as const,
    enabled: false, // Disabled for development
  },
  {
    name: 'NO_SQL_INJECTION',
    pattern: /\$where|\$ne|\$gt|\$lt|\$regex|\$exists|\$in|\$nin/i,
    severity: 'High' as const,
    enabled: true,
  },
];

// WAF Middleware
export const wafMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  try {
    // Check request size
    const contentLength = parseInt(req.get('content-length') || '0', 10);
    if (contentLength > config.waf.maxRequestSizeBytes) {
      logSecurityEvent(EventType.WAF_BLOCKED, 'Request size exceeded limit', {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        contentLength,
        maxSize: config.waf.maxRequestSizeBytes,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });

      res.status(413).json({
        success: false,
        message: 'Request too large',
        code: 'REQUEST_TOO_LARGE',
      });
      return;
    }

    // Check URL for malicious patterns
    const url = req.url;
    const wafResult = checkWafRules(url, 'URL');
    if (wafResult.blocked) {
      logSecurityEvent(EventType.WAF_BLOCKED, `WAF blocked request: ${wafResult.message}`, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        rule: wafResult.rule,
        severity: wafResult.severity,
        url,
        riskLevel: SecurityRiskLevel.HIGH,
      });

      res.status(403).json({
        success: false,
        message: 'Request blocked by security policy',
        code: 'WAF_BLOCKED',
      });
      return;
    }

    // Check request body for malicious patterns
    if (req.body && typeof req.body === 'object') {
      const bodyString = JSON.stringify(req.body);
      const bodyWafResult = checkWafRules(bodyString, 'BODY');
      if (bodyWafResult.blocked) {
        logSecurityEvent(EventType.WAF_BLOCKED, `WAF blocked request body: ${bodyWafResult.message}`, {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          rule: bodyWafResult.rule,
          severity: bodyWafResult.severity,
          riskLevel: SecurityRiskLevel.HIGH,
        });

        res.status(403).json({
          success: false,
          message: 'Request blocked by security policy',
          code: 'WAF_BLOCKED',
        });
        return;
      }
    }

    // Check headers for malicious patterns
    const headersString = JSON.stringify(req.headers);
    const headersWafResult = checkWafRules(headersString, 'HEADERS');
    if (headersWafResult.blocked) {
      logSecurityEvent(EventType.WAF_BLOCKED, `WAF blocked request headers: ${headersWafResult.message}`, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        rule: headersWafResult.rule,
        severity: headersWafResult.severity,
        riskLevel: SecurityRiskLevel.HIGH,
      });

      res.status(403).json({
        success: false,
        message: 'Request blocked by security policy',
        code: 'WAF_BLOCKED',
      });
      return;
    }

    next();
  } catch (error) {
    logger.error('WAF middleware error', { error });
    next(); // Continue even if WAF fails
  }
};

// Check WAF rules against input
function checkWafRules(input: string, source: string): WafResult {
  for (const rule of WAF_RULES) {
    if (!rule.enabled) continue;

    if (rule.pattern.test(input)) {
      return {
        blocked: true,
        rule: rule.name,
        severity: rule.severity,
        message: `Potential ${rule.name.toLowerCase().replace(/_/g, ' ')} detected in ${source}`,
      };
    }
  }

  return {
    blocked: false,
    message: 'Request passed WAF checks',
  };
}

// Rate limiting middleware
export const createRateLimit = (options: {
  windowMs: number;
  max: number;
  message?: string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}) => {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: {
      success: false,
      message: options.message || 'Too many requests, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    skipFailedRequests: options.skipFailedRequests || false,
    handler: (req, res) => {
      logSecurityEvent(EventType.RATE_LIMIT_EXCEEDED, 'Rate limit exceeded', {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });

      res.status(429).json({
        success: false,
        message: options.message || 'Too many requests, please try again later',
        code: 'RATE_LIMIT_EXCEEDED',
      });
    },
  });
};

// General API rate limiting
export const apiRateLimit = createRateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMaxRequests,
  message: 'Too many API requests, please try again later',
});

// Login rate limiting
export const loginRateLimit = createRateLimit({
  windowMs: config.security.rateLimitLoginWindowMs,
  max: config.security.rateLimitLoginMax,
  message: 'Too many login attempts, please try again later',
  skipSuccessfulRequests: true,
});

// Registration rate limiting
export const registerRateLimit = createRateLimit({
  windowMs: config.security.rateLimitRegisterWindowMs,
  max: config.security.rateLimitRegisterMax,
  message: 'Too many registration attempts, please try again later',
  skipSuccessfulRequests: true,
});

// WAF rate limiting
export const wafRateLimit = createRateLimit({
  windowMs: config.waf.rateLimitWindowMinutes * 60 * 1000,
  max: config.waf.rateLimitMaxRequests,
  message: 'Too many requests, please try again later',
});

// Security headers middleware
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      manifestSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard: { action: 'deny' },
  dnsPrefetchControl: { allow: false },
  ieNoOpen: true,
  permittedCrossDomainPolicies: false,
});

// Request logging middleware
export const requestLogging = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    logger.info('HTTP Request', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      contentLength: req.get('content-length'),
    });
  });
  
  next();
};

// IP whitelist middleware
export const ipWhitelist = (allowedIPs: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIP = req.ip;
    
    if (allowedIPs.length > 0 && clientIP && !allowedIPs.includes(clientIP)) {
      logSecurityEvent(EventType.SECURITY_VIOLATION, 'IP not in whitelist', {
        ipAddress: clientIP,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        riskLevel: SecurityRiskLevel.HIGH,
      });

      res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'IP_NOT_ALLOWED',
      });
      return;
    }
    
    next();
  };
};

// Request size limiting middleware
export const requestSizeLimit = (maxSize: number) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = parseInt(req.get('content-length') || '0', 10);
    
    if (contentLength > maxSize) {
      logSecurityEvent(EventType.SECURITY_VIOLATION, 'Request size exceeded', {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        contentLength,
        maxSize,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });

      res.status(413).json({
        success: false,
        message: 'Request too large',
        code: 'REQUEST_TOO_LARGE',
      });
      return;
    }
    
    next();
  };
};

// CORS middleware
export const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (config.cors.origins.includes(origin)) {
      callback(null, true);
    } else {
      logSecurityEvent(EventType.SECURITY_VIOLATION, 'CORS origin not allowed', {
        origin,
        riskLevel: SecurityRiskLevel.MEDIUM,
      });
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400, // 24 hours
};
