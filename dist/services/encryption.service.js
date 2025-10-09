"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptionService = exports.EncryptionService = void 0;
const crypto_1 = __importDefault(require("crypto"));
const config_1 = require("../config");
const logger_1 = require("../config/logger");
class EncryptionService {
    masterKey;
    constructor() {
        this.masterKey = this.initializeMasterKey();
    }
    async encrypt(plaintext, context = '') {
        if (!plaintext) {
            throw new Error('Plaintext cannot be null or empty');
        }
        try {
            const dek = await this.generateDataEncryptionKey();
            const { encryptedValue, nonce, authTag } = this.encryptWithAesGcm(plaintext, dek.key, context);
            const { encryptedDek, dekNonce, dekAuthTag } = this.encryptDek(dek.key, context);
            const result = {
                encryptedValue: encryptedValue.toString('base64'),
                encryptedDek: encryptedDek.toString('base64'),
                algorithm: config_1.config.encryption.algorithm,
                keyId: config_1.config.encryption.masterKeyId,
                nonce: nonce.toString('base64'),
                authTag: authTag.toString('base64'),
                dekNonce: dekNonce.toString('base64'),
                dekAuthTag: dekAuthTag.toString('base64'),
                context,
                createdAt: new Date(),
            };
            logger_1.logger.debug('Successfully encrypted data with envelope encryption', {
                keyId: config_1.config.encryption.masterKeyId,
                dataLength: plaintext.length,
            });
            return result;
        }
        catch (error) {
            logger_1.logger.error('Failed to encrypt data with envelope encryption', { error });
            throw new Error('Encryption failed');
        }
    }
    async decrypt(encryptedData) {
        if (!encryptedData) {
            throw new Error('Encrypted data cannot be null');
        }
        try {
            const encryptedDekBytes = Buffer.from(encryptedData.encryptedDek, 'base64');
            const dekNonceBytes = Buffer.from(encryptedData.dekNonce, 'base64');
            const dekAuthTagBytes = Buffer.from(encryptedData.dekAuthTag, 'base64');
            const dekBytes = this.decryptDek(encryptedDekBytes, dekNonceBytes, dekAuthTagBytes, encryptedData.context);
            const encryptedValueBytes = Buffer.from(encryptedData.encryptedValue, 'base64');
            const nonceBytes = Buffer.from(encryptedData.nonce, 'base64');
            const authTagBytes = Buffer.from(encryptedData.authTag, 'base64');
            const plaintext = this.decryptWithAesGcm(encryptedValueBytes, dekBytes, nonceBytes, authTagBytes, encryptedData.context);
            logger_1.logger.debug('Successfully decrypted data with envelope encryption', {
                keyId: encryptedData.keyId,
            });
            return plaintext;
        }
        catch (error) {
            logger_1.logger.error('Failed to decrypt data with envelope encryption', {
                error,
                keyId: encryptedData.keyId,
            });
            throw new Error('Decryption failed');
        }
    }
    async generateDataEncryptionKey() {
        const key = crypto_1.default.randomBytes(config_1.config.encryption.keyLength);
        const dek = {
            id: crypto_1.default.randomUUID(),
            key,
            algorithm: config_1.config.encryption.algorithm,
            expiresAt: new Date(Date.now() + config_1.config.encryption.keyRotationDays * 24 * 60 * 60 * 1000),
        };
        logger_1.logger.debug('Generated new DEK', { dekId: dek.id });
        return dek;
    }
    async rotateKeys() {
        try {
            this.masterKey = this.initializeMasterKey();
            logger_1.logger.info('Successfully rotated encryption keys', {
                keyId: config_1.config.encryption.masterKeyId,
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to rotate encryption keys', {
                error,
                keyId: config_1.config.encryption.masterKeyId,
            });
            throw error;
        }
    }
    initializeMasterKey() {
        const fixedSeed = 'NexusPay-Development-Master-Key-2025-Fixed-Seed';
        const hash = crypto_1.default.createHash('sha256');
        hash.update(fixedSeed);
        return hash.digest();
    }
    encryptWithAesGcm(plaintext, key, context) {
        const plaintextBytes = Buffer.from(plaintext, 'utf8');
        const nonce = crypto_1.default.randomBytes(config_1.config.encryption.nonceLength);
        const contextBytes = Buffer.from(context, 'utf8');
        const cipher = crypto_1.default.createCipheriv('aes-256-gcm', key, nonce);
        cipher.setAAD(contextBytes);
        let encryptedValue = cipher.update(plaintextBytes);
        encryptedValue = Buffer.concat([encryptedValue, cipher.final()]);
        const authTag = cipher.getAuthTag();
        return {
            encryptedValue,
            nonce,
            authTag,
        };
    }
    decryptWithAesGcm(encryptedValue, key, nonce, authTag, context) {
        const contextBytes = Buffer.from(context, 'utf8');
        const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(authTag);
        decipher.setAAD(contextBytes);
        let plaintext = decipher.update(encryptedValue);
        plaintext = Buffer.concat([plaintext, decipher.final()]);
        return plaintext.toString('utf8');
    }
    encryptDek(dek, context) {
        const contextBytes = Buffer.from(context, 'utf8');
        const nonce = crypto_1.default.randomBytes(config_1.config.encryption.nonceLength);
        const cipher = crypto_1.default.createCipheriv('aes-256-gcm', this.masterKey, nonce);
        cipher.setAAD(contextBytes);
        let encryptedDek = cipher.update(dek);
        encryptedDek = Buffer.concat([encryptedDek, cipher.final()]);
        return {
            encryptedDek,
            dekNonce: nonce,
            dekAuthTag: cipher.getAuthTag(),
        };
    }
    decryptDek(encryptedDek, nonce, authTag, context) {
        const contextBytes = Buffer.from(context, 'utf8');
        const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', this.masterKey, nonce);
        decipher.setAuthTag(authTag);
        decipher.setAAD(contextBytes);
        let dek = decipher.update(encryptedDek);
        dek = Buffer.concat([dek, decipher.final()]);
        return dek;
    }
}
exports.EncryptionService = EncryptionService;
exports.encryptionService = new EncryptionService();
//# sourceMappingURL=encryption.service.js.map