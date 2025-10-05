export declare enum UserRole {
    CUSTOMER = "customer",
    STAFF = "staff",
    ADMIN = "admin"
}
export declare enum PaymentStatus {
    DRAFT = "draft",
    PENDING_VERIFICATION = "pending_verification",
    VERIFIED = "verified",
    REJECTED = "rejected",
    SUBMITTED_TO_SWIFT = "submitted_to_swift",
    COMPLETED = "completed",
    FAILED = "failed"
}
export declare enum SecurityRiskLevel {
    LOW = "Low",
    MEDIUM = "Medium",
    HIGH = "High",
    CRITICAL = "Critical"
}
export declare enum EventType {
    USER_REGISTERED = "USER_REGISTERED",
    USER_LOGIN = "USER_LOGIN",
    USER_LOGOUT = "USER_LOGOUT",
    LOGIN_FAILED = "LOGIN_FAILED",
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
    PAYMENT_CREATED = "PAYMENT_CREATED",
    PAYMENT_UPDATED = "PAYMENT_UPDATED",
    PAYMENT_SUBMITTED = "PAYMENT_SUBMITTED",
    PAYMENT_VERIFIED = "PAYMENT_VERIFIED",
    PAYMENT_REJECTED = "PAYMENT_REJECTED",
    PAYMENT_SWIFT_SUBMITTED = "PAYMENT_SWIFT_SUBMITTED",
    SECURITY_VIOLATION = "SECURITY_VIOLATION",
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
    WAF_BLOCKED = "WAF_BLOCKED",
    SYSTEM_ERROR = "SYSTEM_ERROR",
    DATABASE_ERROR = "DATABASE_ERROR",
    SWIFT_CONNECTION_ERROR = "SWIFT_CONNECTION_ERROR"
}
export declare enum HttpStatusCode {
    OK = 200,
    CREATED = 201,
    NO_CONTENT = 204,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    CONFLICT = 409,
    UNPROCESSABLE_ENTITY = 422,
    TOO_MANY_REQUESTS = 429,
    INTERNAL_SERVER_ERROR = 500,
    SERVICE_UNAVAILABLE = 503
}
export declare enum EncryptionAlgorithm {
    AES_256_GCM = "aes-256-gcm",
    AES_128_GCM = "aes-128-gcm"
}
export declare enum SwiftMessageType {
    MT103 = "MT103",
    MT202 = "MT202",
    MT210 = "MT210"
}
export declare enum SwiftStatus {
    ACCEPTED = "ACCP",
    REJECTED = "RJCT",
    PENDING = "PEND",
    COMPLETED = "COMP"
}
//# sourceMappingURL=enums.d.ts.map