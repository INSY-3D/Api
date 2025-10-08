// NexusPay API Types - Task 2 Compliant
import { Request } from 'express';
import { User, Payment, UserSession } from '@prisma/client';

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: User;
  session?: UserSession;
}

// JWT Payload interface
export interface JWTPayload {
  userId: string;
  email?: string;
  role: string;
  sessionId: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

// API Response interface
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: string[];
  code?: string;
}

// Pagination interface
export interface PaginationDto {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

// User DTOs
export interface UserDto {
  id: string;
  fullName: string;
  email?: string;
  role: string;
  createdAt: Date;
}

export interface CreateUserDto {
  fullName: string;
  saId: string;
  accountNumber: string;
  email?: string;
  password: string;
}

export interface LoginDto {
  usernameOrEmail: string;
  accountNumber: string;
  password: string;
  otp?: string;
  tempEmail?: string; // For users without registered email who need OTP
}

export interface AuthResponse {
  message: string;
  user: UserDto;
  accessToken: string;
  refreshToken: string;
  expiresIn: string;
  mfa?: string;
  unknownDevice?: boolean;
  hasEmail?: boolean; // Indicates if user has registered email
}

// Payment DTOs
export interface PaymentDto {
  id: string;
  amount: number;
  currency: string;
  reference?: string;
  purpose?: string;
  beneficiaryName?: string;
  beneficiaryBank?: string;
  swiftCode?: string;
  accountNumber?: string;
  iban?: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
  staffVerifiedAt?: Date;
  submittedToSwiftAt?: Date;
  completedAt?: Date;
  customerName?: string;
  customerEmail?: string;
}

export interface CreatePaymentDto {
  amount: string;
  currency: string;
  provider: string;
  idempotencyKey: string;
  reference?: string;
  purpose?: string;
}

export interface UpdateBeneficiaryDto {
  beneficiaryName: string;
  beneficiaryAccountNumber: string;
  swiftBic: string;
  beneficiaryIban?: string;
  beneficiaryAddress: string;
  beneficiaryCity: string;
  beneficiaryPostalCode: string;
  beneficiaryCountry: string;
}

export interface SubmitPaymentDto {
  reference: string;
  purpose: string;
  otp?: string;
}

export interface PaymentListResponse {
  payments: PaymentDto[];
  pagination: PaginationDto;
}

// Staff DTOs
export interface StaffPaymentDto {
  id: string;
  amount: number;
  currency: string;
  reference?: string;
  purpose?: string;
  beneficiaryName?: string;
  beneficiaryBank?: string;
  swiftCode?: string;
  accountNumber: string;
  iban?: string;
  bankAddress?: string;
  bankCity?: string;
  bankPostalCode?: string;
  bankCountry?: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
  customerName: string;
  customerEmail?: string;
}

export interface StaffPaymentListResponse {
  payments: StaffPaymentDto[];
  pagination: PaginationDto;
}

export interface VerifyPaymentDto {
  action: 'approve' | 'reject';
  notes?: string;
}

export interface VerifyPaymentResponse {
  message: string;
  paymentId: string;
  status: string;
}

// Encryption types
export interface EncryptedData {
  encryptedValue: string;
  encryptedDek: string;
  algorithm: string;
  keyId: string;
  nonce: string;
  authTag: string;
  dekNonce: string;
  dekAuthTag: string;
  context: string;
  createdAt: Date;
}

export interface DataEncryptionKey {
  id: string;
  key: Buffer;
  algorithm: string;
  expiresAt: Date;
}

// SWIFT types
export interface SwiftPaymentMessage {
  paymentId: string;
  messageType: string;
  senderBic: string;
  receiverBic: string;
  amount: number;
  currency: string;
  debitAccount: string;
  creditAccount: string;
  beneficiaryName: string;
  beneficiaryAddress: string;
  paymentPurpose: string;
  reference: string;
  valueDate: Date;
  orderingCustomer: string;
  orderingCustomerAccount: string;
  remittanceInformation: string;
}

export interface SwiftSubmissionResult {
  success: boolean;
  swiftReference?: string;
  status: string;
  message: string;
  errorCode?: string;
  errorDescription?: string;
  submittedAt: Date;
}

export interface SwiftHealthResult {
  isHealthy: boolean;
  status: string;
  responseTime: number;
  checkedAt: Date;
  errorMessage?: string;
}

export interface SwiftStatusResult {
  success: boolean;
  swiftReference: string;
  status: string;
  statusDescription: string;
  lastUpdated: Date;
  reasonCode?: string;
  reasonDescription?: string;
}

export interface SwiftCancellationResult {
  success: boolean;
  swiftReference: string;
  status: string;
  message: string;
  errorCode?: string;
  errorDescription?: string;
  processedAt: Date;
}

// Audit types
export interface AuditEntry {
  id: string;
  sequenceNumber: number;
  userId?: string;
  eventType: string;
  eventData: string;
  entityId?: string;
  entityType?: string;
  ipAddress?: string;
  userAgent?: string;
  riskLevel: string;
  hash: string;
  previousHash?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}

export interface SecurityEventData {
  userId?: string;
  eventType: string;
  description: string;
  ipAddress?: string;
  userAgent?: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  metadata?: Record<string, any>;
}

// Performance types
export interface PerformanceMetric {
  id: number;
  endpoint: string;
  method: string;
  responseTime: number;
  statusCode: number;
  timestamp: Date;
}

export interface HealthCheck {
  id: number;
  service: string;
  status: string;
  responseTime?: number;
  error?: string;
  timestamp: Date;
}

// Validation types
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
}

// Rate limiting types
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: Date;
  retryAfter?: number;
}

// WAF types
export interface WafRule {
  name: string;
  pattern: RegExp;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  enabled: boolean;
}

export interface WafResult {
  blocked: boolean;
  rule?: string;
  severity?: string;
  message: string;
}

// Error types
export interface ApiError extends Error {
  statusCode: number;
  code: string;
  details?: any;
}

// Middleware types
export interface MiddlewareConfig {
  enabled: boolean;
  options?: Record<string, any>;
}

// Service types
export interface ServiceConfig {
  name: string;
  enabled: boolean;
  config: Record<string, any>;
}

// Database types
export interface DatabaseConfig {
  url: string;
  ssl: boolean;
  pool: {
    min: number;
    max: number;
    idle: number;
  };
}

// Monitoring types
export interface MetricsConfig {
  enabled: boolean;
  port: number;
  path: string;
  collectDefaultMetrics: boolean;
}

// Backup types
export interface BackupConfig {
  enabled: boolean;
  schedule: string;
  retention: number;
  encryption: boolean;
}

// Export all types
export * from './validation';
export * from './enums';
