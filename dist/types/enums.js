"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SwiftStatus = exports.SwiftMessageType = exports.EncryptionAlgorithm = exports.HttpStatusCode = exports.EventType = exports.SecurityRiskLevel = exports.PaymentStatus = exports.UserRole = void 0;
var UserRole;
(function (UserRole) {
    UserRole["CUSTOMER"] = "customer";
    UserRole["STAFF"] = "staff";
    UserRole["ADMIN"] = "admin";
})(UserRole || (exports.UserRole = UserRole = {}));
var PaymentStatus;
(function (PaymentStatus) {
    PaymentStatus["DRAFT"] = "draft";
    PaymentStatus["PENDING_VERIFICATION"] = "pending_verification";
    PaymentStatus["VERIFIED"] = "verified";
    PaymentStatus["REJECTED"] = "rejected";
    PaymentStatus["SUBMITTED_TO_SWIFT"] = "submitted_to_swift";
    PaymentStatus["COMPLETED"] = "completed";
    PaymentStatus["FAILED"] = "failed";
})(PaymentStatus || (exports.PaymentStatus = PaymentStatus = {}));
var SecurityRiskLevel;
(function (SecurityRiskLevel) {
    SecurityRiskLevel["LOW"] = "Low";
    SecurityRiskLevel["MEDIUM"] = "Medium";
    SecurityRiskLevel["HIGH"] = "High";
    SecurityRiskLevel["CRITICAL"] = "Critical";
})(SecurityRiskLevel || (exports.SecurityRiskLevel = SecurityRiskLevel = {}));
var EventType;
(function (EventType) {
    EventType["USER_REGISTERED"] = "USER_REGISTERED";
    EventType["USER_LOGIN"] = "USER_LOGIN";
    EventType["USER_LOGOUT"] = "USER_LOGOUT";
    EventType["LOGIN_FAILED"] = "LOGIN_FAILED";
    EventType["ACCOUNT_LOCKED"] = "ACCOUNT_LOCKED";
    EventType["PAYMENT_CREATED"] = "PAYMENT_CREATED";
    EventType["PAYMENT_UPDATED"] = "PAYMENT_UPDATED";
    EventType["PAYMENT_SUBMITTED"] = "PAYMENT_SUBMITTED";
    EventType["PAYMENT_VERIFIED"] = "PAYMENT_VERIFIED";
    EventType["PAYMENT_REJECTED"] = "PAYMENT_REJECTED";
    EventType["PAYMENT_SWIFT_SUBMITTED"] = "PAYMENT_SWIFT_SUBMITTED";
    EventType["SECURITY_VIOLATION"] = "SECURITY_VIOLATION";
    EventType["SUSPICIOUS_ACTIVITY"] = "SUSPICIOUS_ACTIVITY";
    EventType["RATE_LIMIT_EXCEEDED"] = "RATE_LIMIT_EXCEEDED";
    EventType["WAF_BLOCKED"] = "WAF_BLOCKED";
    EventType["SYSTEM_ERROR"] = "SYSTEM_ERROR";
    EventType["DATABASE_ERROR"] = "DATABASE_ERROR";
    EventType["SWIFT_CONNECTION_ERROR"] = "SWIFT_CONNECTION_ERROR";
})(EventType || (exports.EventType = EventType = {}));
var HttpStatusCode;
(function (HttpStatusCode) {
    HttpStatusCode[HttpStatusCode["OK"] = 200] = "OK";
    HttpStatusCode[HttpStatusCode["CREATED"] = 201] = "CREATED";
    HttpStatusCode[HttpStatusCode["NO_CONTENT"] = 204] = "NO_CONTENT";
    HttpStatusCode[HttpStatusCode["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    HttpStatusCode[HttpStatusCode["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
    HttpStatusCode[HttpStatusCode["FORBIDDEN"] = 403] = "FORBIDDEN";
    HttpStatusCode[HttpStatusCode["NOT_FOUND"] = 404] = "NOT_FOUND";
    HttpStatusCode[HttpStatusCode["CONFLICT"] = 409] = "CONFLICT";
    HttpStatusCode[HttpStatusCode["UNPROCESSABLE_ENTITY"] = 422] = "UNPROCESSABLE_ENTITY";
    HttpStatusCode[HttpStatusCode["TOO_MANY_REQUESTS"] = 429] = "TOO_MANY_REQUESTS";
    HttpStatusCode[HttpStatusCode["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
    HttpStatusCode[HttpStatusCode["SERVICE_UNAVAILABLE"] = 503] = "SERVICE_UNAVAILABLE";
})(HttpStatusCode || (exports.HttpStatusCode = HttpStatusCode = {}));
var EncryptionAlgorithm;
(function (EncryptionAlgorithm) {
    EncryptionAlgorithm["AES_256_GCM"] = "aes-256-gcm";
    EncryptionAlgorithm["AES_128_GCM"] = "aes-128-gcm";
})(EncryptionAlgorithm || (exports.EncryptionAlgorithm = EncryptionAlgorithm = {}));
var SwiftMessageType;
(function (SwiftMessageType) {
    SwiftMessageType["MT103"] = "MT103";
    SwiftMessageType["MT202"] = "MT202";
    SwiftMessageType["MT210"] = "MT210";
})(SwiftMessageType || (exports.SwiftMessageType = SwiftMessageType = {}));
var SwiftStatus;
(function (SwiftStatus) {
    SwiftStatus["ACCEPTED"] = "ACCP";
    SwiftStatus["REJECTED"] = "RJCT";
    SwiftStatus["PENDING"] = "PEND";
    SwiftStatus["COMPLETED"] = "COMP";
})(SwiftStatus || (exports.SwiftStatus = SwiftStatus = {}));
//# sourceMappingURL=enums.js.map