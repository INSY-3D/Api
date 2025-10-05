// NexusPay API Enums - Task 2 Compliant

export enum UserRole {
  CUSTOMER = 'customer',
  STAFF = 'staff',
  ADMIN = 'admin'
}

export enum PaymentStatus {
  DRAFT = 'draft',
  PENDING_VERIFICATION = 'pending_verification',
  VERIFIED = 'verified',
  REJECTED = 'rejected',
  SUBMITTED_TO_SWIFT = 'submitted_to_swift',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

export enum SecurityRiskLevel {
  LOW = 'Low',
  MEDIUM = 'Medium',
  HIGH = 'High',
  CRITICAL = 'Critical'
}

export enum EventType {
  // Authentication events
  USER_REGISTERED = 'USER_REGISTERED',
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  
  // Payment events
  PAYMENT_CREATED = 'PAYMENT_CREATED',
  PAYMENT_UPDATED = 'PAYMENT_UPDATED',
  PAYMENT_SUBMITTED = 'PAYMENT_SUBMITTED',
  PAYMENT_VERIFIED = 'PAYMENT_VERIFIED',
  PAYMENT_REJECTED = 'PAYMENT_REJECTED',
  PAYMENT_SWIFT_SUBMITTED = 'PAYMENT_SWIFT_SUBMITTED',
  
  // Security events
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  WAF_BLOCKED = 'WAF_BLOCKED',
  
  // System events
  SYSTEM_ERROR = 'SYSTEM_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  SWIFT_CONNECTION_ERROR = 'SWIFT_CONNECTION_ERROR'
}

export enum HttpStatusCode {
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

export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  AES_128_GCM = 'aes-128-gcm'
}

export enum SwiftMessageType {
  MT103 = 'MT103',
  MT202 = 'MT202',
  MT210 = 'MT210'
}

export enum SwiftStatus {
  ACCEPTED = 'ACCP',
  REJECTED = 'RJCT',
  PENDING = 'PEND',
  COMPLETED = 'COMP'
}
