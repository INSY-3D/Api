"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.maskSaId = exports.maskEmail = exports.maskAccountNumber = exports.formatAccountNumber = exports.formatIban = exports.formatSwiftBic = exports.isValidIban = exports.isValidSwiftBic = exports.isValidAmount = exports.isValidCurrency = exports.isValidPassword = exports.isValidEmail = exports.isValidAccountNumber = exports.isValidSaId = exports.isValidFullName = exports.sanitizeAlphanumeric = exports.sanitizeNumeric = exports.sanitizeEmail = exports.sanitizeString = exports.VALIDATION_MESSAGES = exports.VALIDATION_PATTERNS = void 0;
exports.VALIDATION_PATTERNS = {
    fullName: /^[A-Za-zÀ-ÿ' \-]{2,100}$/,
    saId: /^[0-9]{13}$/,
    accountNumber: /^[0-9]{8,12}$/,
    email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    currency: /^[A-Z]{3}$/,
    amount: /^\d{1,12}(\.\d{1,2})?$/,
    swiftBic: /^[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?$/,
    iban: /^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}$/
};
exports.VALIDATION_MESSAGES = {
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
    minLength: (min) => `Minimum length is ${min} characters`,
    maxLength: (max) => `Maximum length is ${max} characters`,
    pattern: 'Invalid format'
};
const sanitizeString = (input, maxLength) => {
    if (!input)
        return '';
    let sanitized = input.replace(/[\x00-\x1F\x7F]/g, '');
    sanitized = sanitized.trim();
    if (sanitized.length > maxLength) {
        sanitized = sanitized.substring(0, maxLength);
    }
    return sanitized;
};
exports.sanitizeString = sanitizeString;
const sanitizeEmail = (email) => {
    if (!email)
        return '';
    let sanitized = email.toLowerCase().trim();
    sanitized = sanitized.replace(/[^a-zA-Z0-9._%+-@]/g, '');
    return sanitized;
};
exports.sanitizeEmail = sanitizeEmail;
const sanitizeNumeric = (input) => {
    if (!input)
        return '';
    return input.replace(/[^0-9]/g, '');
};
exports.sanitizeNumeric = sanitizeNumeric;
const sanitizeAlphanumeric = (input) => {
    if (!input)
        return '';
    return input.replace(/[^a-zA-Z0-9]/g, '');
};
exports.sanitizeAlphanumeric = sanitizeAlphanumeric;
const isValidFullName = (name) => {
    return exports.VALIDATION_PATTERNS.fullName.test(name);
};
exports.isValidFullName = isValidFullName;
const isValidSaId = (saId) => {
    return exports.VALIDATION_PATTERNS.saId.test(saId);
};
exports.isValidSaId = isValidSaId;
const isValidAccountNumber = (accountNumber) => {
    return exports.VALIDATION_PATTERNS.accountNumber.test(accountNumber);
};
exports.isValidAccountNumber = isValidAccountNumber;
const isValidEmail = (email) => {
    return exports.VALIDATION_PATTERNS.email.test(email);
};
exports.isValidEmail = isValidEmail;
const isValidPassword = (password) => {
    return exports.VALIDATION_PATTERNS.password.test(password);
};
exports.isValidPassword = isValidPassword;
const isValidCurrency = (currency) => {
    return exports.VALIDATION_PATTERNS.currency.test(currency);
};
exports.isValidCurrency = isValidCurrency;
const isValidAmount = (amount) => {
    return exports.VALIDATION_PATTERNS.amount.test(amount);
};
exports.isValidAmount = isValidAmount;
const isValidSwiftBic = (swiftBic) => {
    return /^[A-Za-z0-9]{8}([A-Za-z0-9]{3})?$/.test(swiftBic);
};
exports.isValidSwiftBic = isValidSwiftBic;
const isValidIban = (iban) => {
    return exports.VALIDATION_PATTERNS.iban.test(iban);
};
exports.isValidIban = isValidIban;
const formatSwiftBic = (swiftBic) => {
    if (!swiftBic)
        return '';
    let formatted = swiftBic.replace(/\s/g, '').toUpperCase();
    if (formatted.length === 8) {
        return formatted;
    }
    else if (formatted.length === 11) {
        return formatted;
    }
    return formatted;
};
exports.formatSwiftBic = formatSwiftBic;
const formatIban = (iban) => {
    if (!iban)
        return '';
    let formatted = iban.replace(/\s/g, '').toUpperCase();
    return formatted.replace(/(.{4})/g, '$1 ').trim();
};
exports.formatIban = formatIban;
const formatAccountNumber = (accountNumber) => {
    if (!accountNumber)
        return '';
    const cleaned = accountNumber.replace(/\D/g, '');
    return cleaned.replace(/(.{4})/g, '$1 ').trim();
};
exports.formatAccountNumber = formatAccountNumber;
const maskAccountNumber = (accountNumber) => {
    if (!accountNumber || accountNumber.length <= 4) {
        return accountNumber;
    }
    const masked = '*'.repeat(accountNumber.length - 4);
    return masked + accountNumber.slice(-4);
};
exports.maskAccountNumber = maskAccountNumber;
const maskEmail = (email) => {
    if (!email)
        return '';
    const [localPart, domain] = email.split('@');
    if (!localPart || !domain)
        return email;
    if (localPart.length <= 2)
        return email;
    const maskedLocal = localPart.substring(0, 2) + '***';
    return `${maskedLocal}@${domain}`;
};
exports.maskEmail = maskEmail;
const maskSaId = (saId) => {
    if (!saId || saId.length !== 13)
        return saId;
    return saId.substring(0, 6) + '***' + saId.substring(9);
};
exports.maskSaId = maskSaId;
//# sourceMappingURL=validation.js.map