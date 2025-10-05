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
export declare const VALIDATION_PATTERNS: ValidationPatterns;
export declare const VALIDATION_MESSAGES: {
    fullName: string;
    saId: string;
    accountNumber: string;
    email: string;
    password: string;
    currency: string;
    amount: string;
    swiftBic: string;
    iban: string;
    required: string;
    minLength: (min: number) => string;
    maxLength: (max: number) => string;
    pattern: string;
};
export declare const sanitizeString: (input: string, maxLength: number) => string;
export declare const sanitizeEmail: (email: string) => string;
export declare const sanitizeNumeric: (input: string) => string;
export declare const sanitizeAlphanumeric: (input: string) => string;
export declare const isValidFullName: (name: string) => boolean;
export declare const isValidSaId: (saId: string) => boolean;
export declare const isValidAccountNumber: (accountNumber: string) => boolean;
export declare const isValidEmail: (email: string) => boolean;
export declare const isValidPassword: (password: string) => boolean;
export declare const isValidCurrency: (currency: string) => boolean;
export declare const isValidAmount: (amount: string) => boolean;
export declare const isValidSwiftBic: (swiftBic: string) => boolean;
export declare const isValidIban: (iban: string) => boolean;
export declare const formatSwiftBic: (swiftBic: string) => string;
export declare const formatIban: (iban: string) => string;
export declare const formatAccountNumber: (accountNumber: string) => string;
export declare const maskAccountNumber: (accountNumber: string) => string;
export declare const maskEmail: (email: string) => string;
export declare const maskSaId: (saId: string) => string;
//# sourceMappingURL=validation.d.ts.map