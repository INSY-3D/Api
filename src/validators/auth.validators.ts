import { z } from 'zod';
import { VALIDATION_PATTERNS } from '@/types/validation';

// Task 2 Compliant: Authentication validation schemas

export const registerSchema = z.object({
  fullName: z.string()
    .min(2, 'Full name must be at least 2 characters')
    .max(100, 'Full name must not exceed 100 characters')
    .regex(VALIDATION_PATTERNS.fullName, 'Invalid full name format'),
  
  saId: z.string()
    .length(13, 'South African ID must be exactly 13 digits')
    .regex(VALIDATION_PATTERNS.saId, 'Invalid SA ID format'),
  
  accountNumber: z.string()
    .min(8, 'Account number must be at least 8 digits')
    .max(12, 'Account number must not exceed 12 digits')
    .regex(VALIDATION_PATTERNS.accountNumber, 'Invalid account number format'),
  
  email: z.string()
    .email('Invalid email format')
    .optional(),
  
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(VALIDATION_PATTERNS.password, 'Password must contain uppercase, lowercase, number, and special character'),
});

export const loginSchema = z.object({
  usernameOrEmail: z.string()
    .min(1, 'Username or email is required')
    .max(254, 'Username or email must not exceed 254 characters'),
  
  accountNumber: z.string()
    .min(8, 'Account number must be at least 8 digits')
    .max(12, 'Account number must not exceed 12 digits')
    .regex(VALIDATION_PATTERNS.accountNumber, 'Invalid account number format'),
  
  password: z.string()
    .min(1, 'Password is required'),
  
  otp: z.string()
    .optional(),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string()
    .min(1, 'Refresh token is required'),
});

export const staffLoginSchema = z.object({
  usernameOrEmail: z.string()
    .min(1, 'Username or email is required')
    .max(254, 'Username or email must not exceed 254 characters'),
  
  accountNumber: z.string()
    .min(1, 'Account number is required')
    .max(18, 'Account number must not exceed 18 characters'),
  
  password: z.string()
    .min(1, 'Password is required'),
  
  otp: z.string()
    .optional(),
});

// Type exports for TypeScript
export type RegisterRequest = z.infer<typeof registerSchema>;
export type LoginRequest = z.infer<typeof loginSchema>;
export type RefreshTokenRequest = z.infer<typeof refreshTokenSchema>;
export type StaffLoginRequest = z.infer<typeof staffLoginSchema>;
