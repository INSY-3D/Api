export declare const config: {
    server: {
        port: number;
        host: string;
        nodeEnv: string;
        isDevelopment: boolean;
        isProduction: boolean;
    };
    database: {
        url: string;
        urlDev: string;
    };
    jwt: {
        secret: string;
        refreshSecret: string;
        expiresIn: string;
        refreshExpiresIn: string;
        issuer: string;
        audience: string;
    };
    encryption: {
        algorithm: string;
        keyLength: number;
        nonceLength: number;
        tagLength: number;
        keyRotationDays: number;
        masterKeyId: string;
        useHsm: boolean;
    };
    argon2: {
        memoryCost: number;
        timeCost: number;
        parallelism: number;
        hashLength: number;
        saltLength: number;
    };
    swift: {
        baseUrl: string;
        clientCertPath: string;
        clientCertPassword: string;
        caCertPath: string;
        senderBic: string;
        timeoutSeconds: number;
        validateServerCert: boolean;
        enableMessageSigning: boolean;
        signingKeyPath: string;
        signingKeyPassword: string;
    };
    security: {
        bcryptWorkFactor: number;
        rateLimitMaxRequests: number;
        rateLimitWindowMs: number;
        rateLimitLoginMax: number;
        rateLimitLoginWindowMs: number;
        rateLimitRegisterMax: number;
        rateLimitRegisterWindowMs: number;
    };
    waf: {
        rateLimitMaxRequests: number;
        rateLimitWindowMinutes: number;
        maxRequestSizeBytes: number;
        enableSqlInjectionDetection: boolean;
        enableXssDetection: boolean;
        enablePathTraversalDetection: boolean;
        enableCommandInjectionDetection: boolean;
    };
    cors: {
        origins: string[];
    };
    audit: {
        signingKey: string;
        chainSalt: string;
    };
    siem: {
        enabled: boolean;
        endpoint: string;
        apiKey: string;
        signingKey: string;
        alertsEnabled: boolean;
        webhookUrl: string;
        useExternalThreatIntel: boolean;
    };
    backup: {
        directory: string;
        retentionDays: number;
        autoBackupEnabled: boolean;
        fullBackupIntervalDays: number;
        incrementalBackupIntervalDays: number;
    };
    performance: {
        enableDetailedMetrics: boolean;
        cacheDefaultExpiryMinutes: number;
        maxCacheSizeMB: number;
    };
    logging: {
        level: string;
        format: string;
        filePath: string;
        maxSize: string;
        maxFiles: number;
    };
    tls: {
        minVersion: string;
        cipherSuites: string;
        certPath: string;
        keyPath: string;
        caPath: string;
    };
    healthCheck: {
        enabled: boolean;
        intervalMs: number;
        timeoutMs: number;
    };
    monitoring: {
        metricsEnabled: boolean;
        metricsPort: number;
        metricsPath: string;
    };
};
export declare const validateConfig: () => void;
//# sourceMappingURL=index.d.ts.map