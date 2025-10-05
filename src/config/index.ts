import dotenv from 'dotenv';
import { logger } from './logger';

// Load environment variables
dotenv.config();

// Task 2 Compliant: Configuration management with validation
export const config = {
  // Server Configuration
  server: {
    port: parseInt(process.env.PORT || '5118', 10),
    host: process.env.HOST || 'localhost',
    nodeEnv: process.env.NODE_ENV || 'development',
    isDevelopment: process.env.NODE_ENV === 'development',
    isProduction: process.env.NODE_ENV === 'production',
  },

  // Database Configuration
  database: {
    url: process.env.DATABASE_URL || process.env.DATABASE_URL_DEV || '',
    urlDev: process.env.DATABASE_URL_DEV || '',
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your-super-secure-jwt-secret-key-here-minimum-32-characters-for-development',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-super-secure-refresh-secret-key-here-minimum-32-characters-for-development',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: process.env.JWT_ISSUER || 'nexuspay-api',
    audience: process.env.JWT_AUDIENCE || 'nexuspay-app',
  },

  // Encryption Configuration
  encryption: {
    algorithm: process.env.ENCRYPTION_ALGORITHM || 'aes-256-gcm',
    keyLength: parseInt(process.env.ENCRYPTION_KEY_LENGTH || '32', 10),
    nonceLength: parseInt(process.env.ENCRYPTION_NONCE_LENGTH || '12', 10),
    tagLength: parseInt(process.env.ENCRYPTION_TAG_LENGTH || '16', 10),
    keyRotationDays: parseInt(process.env.ENCRYPTION_KEY_ROTATION_DAYS || '90', 10),
    masterKeyId: process.env.ENCRYPTION_MASTER_KEY_ID || 'nexuspay-master-key-2025',
    useHsm: process.env.ENCRYPTION_USE_HSM === 'true',
  },

  // Argon2id Configuration
  argon2: {
    memoryCost: parseInt(process.env.ARGON2_MEMORY_COST || '65536', 10),
    timeCost: parseInt(process.env.ARGON2_TIME_COST || '3', 10),
    parallelism: parseInt(process.env.ARGON2_PARALLELISM || '1', 10),
    hashLength: parseInt(process.env.ARGON2_HASH_LENGTH || '32', 10),
    saltLength: parseInt(process.env.ARGON2_SALT_LENGTH || '16', 10),
  },

  // SWIFT Configuration
  swift: {
    baseUrl: process.env.SWIFT_BASE_URL || 'https://swift-gateway.nexuspay.bank',
    clientCertPath: process.env.SWIFT_CLIENT_CERT_PATH || '',
    clientCertPassword: process.env.SWIFT_CLIENT_CERT_PASSWORD || '',
    caCertPath: process.env.SWIFT_CA_CERT_PATH || '',
    senderBic: process.env.SWIFT_SENDER_BIC || 'NEXUSZAJJ',
    timeoutSeconds: parseInt(process.env.SWIFT_TIMEOUT_SECONDS || '30', 10),
    validateServerCert: process.env.SWIFT_VALIDATE_SERVER_CERT === 'true',
    enableMessageSigning: process.env.SWIFT_ENABLE_MESSAGE_SIGNING === 'true',
    signingKeyPath: process.env.SWIFT_SIGNING_KEY_PATH || '',
    signingKeyPassword: process.env.SWIFT_SIGNING_KEY_PASSWORD || '',
  },

  // Security Configuration
  security: {
    bcryptWorkFactor: parseInt(process.env.BCRYPT_WORK_FACTOR || '12', 10),
    rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    rateLimitLoginMax: parseInt(process.env.RATE_LIMIT_LOGIN_MAX || '5', 10),
    rateLimitLoginWindowMs: parseInt(process.env.RATE_LIMIT_LOGIN_WINDOW_MS || '900000', 10),
    rateLimitRegisterMax: parseInt(process.env.RATE_LIMIT_REGISTER_MAX || '3', 10),
    rateLimitRegisterWindowMs: parseInt(process.env.RATE_LIMIT_REGISTER_WINDOW_MS || '3600000', 10),
  },

  // WAF Configuration
  waf: {
    rateLimitMaxRequests: parseInt(process.env.WAF_RATE_LIMIT_MAX_REQUESTS || '1000', 10),
    rateLimitWindowMinutes: parseInt(process.env.WAF_RATE_LIMIT_WINDOW_MINUTES || '1', 10),
    maxRequestSizeBytes: parseInt(process.env.WAF_MAX_REQUEST_SIZE_BYTES || '10485760', 10),
    enableSqlInjectionDetection: process.env.WAF_ENABLE_SQL_INJECTION_DETECTION === 'true',
    enableXssDetection: process.env.WAF_ENABLE_XSS_DETECTION === 'true',
    enablePathTraversalDetection: process.env.WAF_ENABLE_PATH_TRAVERSAL_DETECTION === 'true',
    enableCommandInjectionDetection: process.env.WAF_ENABLE_COMMAND_INJECTION_DETECTION === 'true',
  },

  // CORS Configuration
  cors: {
    origins: process.env.CORS_ORIGINS?.split(',') || [
      'http://localhost:5173',
      'https://localhost:5173',
      'http://localhost:5174',
      'https://localhost:5174'
    ],
  },

  // Audit Configuration
  audit: {
    signingKey: process.env.AUDIT_SIGNING_KEY || 'CHANGE_IN_PRODUCTION_STRONG_KEY_FOR_AUDIT_INTEGRITY',
    chainSalt: process.env.AUDIT_CHAIN_SALT || 'CHANGE_IN_PRODUCTION_SALT_FOR_HASH_CHAIN',
  },

  // SIEM Configuration
  siem: {
    enabled: process.env.SIEM_ENABLED === 'true',
    endpoint: process.env.SIEM_ENDPOINT || 'https://siem.company.com/api/events',
    apiKey: process.env.SIEM_API_KEY || '',
    signingKey: process.env.SIEM_SIGNING_KEY || 'CHANGE_IN_PRODUCTION_SIEM_SIGNING_KEY',
    alertsEnabled: process.env.SIEM_ALERTS_ENABLED === 'true',
    webhookUrl: process.env.SIEM_WEBHOOK_URL || '',
    useExternalThreatIntel: process.env.SIEM_USE_EXTERNAL_THREAT_INTEL === 'true',
  },

  // Backup Configuration
  backup: {
    directory: process.env.BACKUP_DIRECTORY || '',
    retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS || '30', 10),
    autoBackupEnabled: process.env.BACKUP_AUTO_BACKUP_ENABLED === 'true',
    fullBackupIntervalDays: parseInt(process.env.BACKUP_FULL_BACKUP_INTERVAL_DAYS || '7', 10),
    incrementalBackupIntervalDays: parseInt(process.env.BACKUP_INCREMENTAL_BACKUP_INTERVAL_DAYS || '1', 10),
  },

  // Performance Configuration
  performance: {
    enableDetailedMetrics: process.env.PERFORMANCE_ENABLE_DETAILED_METRICS === 'true',
    cacheDefaultExpiryMinutes: parseInt(process.env.PERFORMANCE_CACHE_DEFAULT_EXPIRY_MINUTES || '15', 10),
    maxCacheSizeMB: parseInt(process.env.PERFORMANCE_MAX_CACHE_SIZE_MB || '100', 10),
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.LOG_FORMAT || 'json',
    filePath: process.env.LOG_FILE_PATH || 'logs/nexuspay-api.log',
    maxSize: process.env.LOG_MAX_SIZE || '20m',
    maxFiles: parseInt(process.env.LOG_MAX_FILES || '5', 10),
  },

  // TLS Configuration
  tls: {
    minVersion: process.env.TLS_MIN_VERSION || 'TLSv1.3',
    cipherSuites: process.env.TLS_CIPHER_SUITES || 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    certPath: process.env.TLS_CERT_PATH || '',
    keyPath: process.env.TLS_KEY_PATH || '',
    caPath: process.env.TLS_CA_PATH || '',
  },

  // Health Check Configuration
  healthCheck: {
    enabled: process.env.HEALTH_CHECK_ENABLED === 'true',
    intervalMs: parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || '30000', 10),
    timeoutMs: parseInt(process.env.HEALTH_CHECK_TIMEOUT_MS || '5000', 10),
  },

  // Monitoring Configuration
  monitoring: {
    metricsEnabled: process.env.METRICS_ENABLED === 'true',
    metricsPort: parseInt(process.env.METRICS_PORT || '9090', 10),
    metricsPath: process.env.METRICS_PATH || '/metrics',
  },
};

// Validate critical configuration
export const validateConfig = (): void => {
  const errors: string[] = [];

  // Validate JWT secrets
  if (config.jwt.secret.length < 32) {
    errors.push('JWT_SECRET must be at least 32 characters long');
  }

  if (config.jwt.refreshSecret.length < 32) {
    errors.push('JWT_REFRESH_SECRET must be at least 32 characters long');
  }

  // Validate database URL
  if (!config.database.url) {
    errors.push('DATABASE_URL is required');
  }

  // Validate encryption configuration
  if (config.encryption.keyLength < 16) {
    errors.push('ENCRYPTION_KEY_LENGTH must be at least 16');
  }

  // Validate Argon2 configuration
  if (config.argon2.memoryCost < 1024) {
    errors.push('ARGON2_MEMORY_COST must be at least 1024');
  }

  if (config.argon2.timeCost < 1) {
    errors.push('ARGON2_TIME_COST must be at least 1');
  }

  // Log validation errors
  if (errors.length > 0) {
    logger.error('Configuration validation failed', { errors });
    throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
  }

  logger.info('Configuration validated successfully');
};

// Initialize configuration validation
validateConfig();
