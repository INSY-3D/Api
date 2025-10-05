// NexusPay API Validation Types - Task 2 Compliant

export interface ValidationPatterns {
  fullName: RegExp;
  saId: RegExp;
  accountNumber: RegExp;
  email: RegExp;
  password: RegExp;
  currency: RegExp;
  amount: RegExp;
  swiftBic: RegExp;
  iban: RegExp;
}

// Task 2 Compliant: RegEx patterns for input validation
export const VALIDATION_PATTERNS: ValidationPatterns = {
  // Full name with international character support
  fullName: /^[A-Za-zÀ-ÿ' \-]{2,100}$/,
  
  // South African ID number (13 digits)
  saId: /^[0-9]{13}$/,
  
  // Account number (8-12 digits)
  accountNumber: /^[0-9]{8,12}$/,
  
  // Email validation
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  
  // Password requirements
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  
  // Currency code (3 uppercase letters)
  currency: /^[A-Z]{3}$/,
  
  // Amount validation (up to 12 digits with 2 decimal places)
  amount: /^\d{1,12}(\.\d{1,2})?$/,
  
  // SWIFT/BIC code validation
  swiftBic: /^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$/,
  
  // IBAN validation (basic format)
  iban: /^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}$/
};

// Validation error messages
export const VALIDATION_MESSAGES = {
  fullName: 'Full name must be 2-100 characters and contain only letters, spaces, hyphens, and apostrophes',
  saId: 'South African ID must be exactly 13 digits',
  accountNumber: 'Account number must be 8-12 digits',
  email: 'Please enter a valid email address',
  password: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character',
  currency: 'Currency must be a valid 3-letter ISO code',
  amount: 'Amount must be a positive number with up to 2 decimal places',
  swiftBic: 'Please enter a valid SWIFT/BIC code',
  iban: 'Please enter a valid IBAN',
  required: 'This field is required',
  minLength: (min: number) => `Minimum length is ${min} characters`,
  maxLength: (max: number) => `Maximum length is ${max} characters`,
  pattern: 'Invalid format'
};

// Sanitization functions
export const sanitizeString = (input: string, maxLength: number): string => {
  if (!input) return '';
  
  // Remove null bytes and control characters
  let sanitized = input.replace(/[\x00-\x1F\x7F]/g, '');
  
  // Trim whitespace
  sanitized = sanitized.trim();
  
  // Limit length
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }
  
  return sanitized;
};

export const sanitizeEmail = (email: string): string => {
  if (!email) return '';
  
  // Convert to lowercase and trim
  let sanitized = email.toLowerCase().trim();
  
  // Remove any characters that aren't valid in email
  sanitized = sanitized.replace(/[^a-zA-Z0-9._%+-@]/g, '');
  
  return sanitized;
};

export const sanitizeNumeric = (input: string): string => {
  if (!input) return '';
  
  // Remove all non-numeric characters
  return input.replace(/[^0-9]/g, '');
};

export const sanitizeAlphanumeric = (input: string): string => {
  if (!input) return '';
  
  // Remove all non-alphanumeric characters
  return input.replace(/[^a-zA-Z0-9]/g, '');
};

// Validation helper functions
export const isValidFullName = (name: string): boolean => {
  return VALIDATION_PATTERNS.fullName.test(name);
};

export const isValidSaId = (saId: string): boolean => {
  return VALIDATION_PATTERNS.saId.test(saId);
};

export const isValidAccountNumber = (accountNumber: string): boolean => {
  return VALIDATION_PATTERNS.accountNumber.test(accountNumber);
};

export const isValidEmail = (email: string): boolean => {
  return VALIDATION_PATTERNS.email.test(email);
};

export const isValidPassword = (password: string): boolean => {
  return VALIDATION_PATTERNS.password.test(password);
};

export const isValidCurrency = (currency: string): boolean => {
  return VALIDATION_PATTERNS.currency.test(currency);
};

export const isValidAmount = (amount: string): boolean => {
  return VALIDATION_PATTERNS.amount.test(amount);
};

export const isValidSwiftBic = (swiftBic: string): boolean => {
  // Use the same pattern as beneficiary validation for consistency
  return /^[A-Za-z0-9]{8}([A-Za-z0-9]{3})?$/.test(swiftBic);
};

export const isValidIban = (iban: string): boolean => {
  return VALIDATION_PATTERNS.iban.test(iban);
};

// Format functions
export const formatSwiftBic = (swiftBic: string): string => {
  if (!swiftBic) return '';
  
  // Remove spaces and convert to uppercase
  let formatted = swiftBic.replace(/\s/g, '').toUpperCase();
  
  // Ensure proper length
  if (formatted.length === 8) {
    return formatted;
  } else if (formatted.length === 11) {
    return formatted;
  }
  
  return formatted;
};

export const formatIban = (iban: string): string => {
  if (!iban) return '';
  
  // Remove spaces and convert to uppercase
  let formatted = iban.replace(/\s/g, '').toUpperCase();
  
  // Add spaces every 4 characters for readability
  return formatted.replace(/(.{4})/g, '$1 ').trim();
};

export const formatAccountNumber = (accountNumber: string): string => {
  if (!accountNumber) return '';
  
  // Remove all non-numeric characters
  const cleaned = accountNumber.replace(/\D/g, '');
  
  // Add spaces every 4 digits for readability
  return cleaned.replace(/(.{4})/g, '$1 ').trim();
};

// Masking functions for sensitive data
export const maskAccountNumber = (accountNumber: string): string => {
  if (!accountNumber || accountNumber.length <= 4) {
    return accountNumber;
  }
  
  const masked = '*'.repeat(accountNumber.length - 4);
  return masked + accountNumber.slice(-4);
};

export const maskEmail = (email: string): string => {
  if (!email) return '';
  
  const [localPart, domain] = email.split('@');
  if (!localPart || !domain) return email;
  
  if (localPart.length <= 2) return email;
  
  const maskedLocal = localPart.substring(0, 2) + '***';
  return `${maskedLocal}@${domain}`;
};

export const maskSaId = (saId: string): string => {
  if (!saId || saId.length !== 13) return saId;
  
  return saId.substring(0, 6) + '***' + saId.substring(9);
};
