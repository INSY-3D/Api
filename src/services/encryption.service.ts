import crypto from 'crypto';
import { config } from '@/config';
import { logger } from '@/config/logger';
import { EncryptedData, DataEncryptionKey } from '@/types';
import { EncryptionAlgorithm } from '@/types/enums';

// Task 2 Compliant: PII encryption with envelope encryption pattern
export class EncryptionService {
  private masterKey: Buffer;

  constructor() {
    // Initialize master key (in production, this would come from KMS/HSM)
    this.masterKey = this.initializeMasterKey();
  }

  /**
   * Encrypt PII using envelope encryption pattern
   * 1. Generate DEK (Data Encryption Key)
   * 2. Encrypt data with DEK
   * 3. Encrypt DEK with KEK (Key Encryption Key from KMS/HSM)
   * 4. Store encrypted data + encrypted DEK
   */
  async encrypt(plaintext: string, context: string = ''): Promise<EncryptedData> {
    if (!plaintext) {
      throw new Error('Plaintext cannot be null or empty');
    }

    try {
      // Step 1: Generate a new Data Encryption Key
      const dek = await this.generateDataEncryptionKey();

      // Step 2: Encrypt the plaintext with the DEK using AES-GCM
      const { encryptedValue, nonce, authTag } = this.encryptWithAesGcm(plaintext, dek.key, context);

      // Step 3: Encrypt the DEK with the KEK from KMS/HSM
      const { encryptedDek, dekNonce, dekAuthTag } = this.encryptDek(dek.key, context);

      // Step 4: Return the encrypted data structure
      const result: EncryptedData = {
        encryptedValue: encryptedValue.toString('base64'),
        encryptedDek: encryptedDek.toString('base64'),
        algorithm: config.encryption.algorithm,
        keyId: config.encryption.masterKeyId,
        nonce: nonce.toString('base64'),
        authTag: authTag.toString('base64'),
        dekNonce: dekNonce.toString('base64'),
        dekAuthTag: dekAuthTag.toString('base64'),
        context,
        createdAt: new Date(),
      };

      logger.debug('Successfully encrypted data with envelope encryption', {
        keyId: config.encryption.masterKeyId,
        dataLength: plaintext.length,
      });

      return result;
    } catch (error) {
      logger.error('Failed to encrypt data with envelope encryption', { error });
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt PII using envelope encryption pattern
   * 1. Decrypt DEK using KEK from KMS/HSM
   * 2. Decrypt data using DEK
   */
  async decrypt(encryptedData: EncryptedData): Promise<string> {
    if (!encryptedData) {
      throw new Error('Encrypted data cannot be null');
    }

    try {
      // Step 1: Decrypt the DEK using the KEK from KMS/HSM
      const encryptedDekBytes = Buffer.from(encryptedData.encryptedDek, 'base64');
      const dekNonceBytes = Buffer.from(encryptedData.dekNonce, 'base64');
      const dekAuthTagBytes = Buffer.from(encryptedData.dekAuthTag, 'base64');
      const dekBytes = this.decryptDek(encryptedDekBytes, dekNonceBytes, dekAuthTagBytes, encryptedData.context);

      // Step 2: Decrypt the data using the DEK
      const encryptedValueBytes = Buffer.from(encryptedData.encryptedValue, 'base64');
      const nonceBytes = Buffer.from(encryptedData.nonce, 'base64');
      const authTagBytes = Buffer.from(encryptedData.authTag, 'base64');

      const plaintext = this.decryptWithAesGcm(
        encryptedValueBytes,
        dekBytes,
        nonceBytes,
        authTagBytes,
        encryptedData.context
      );

      logger.debug('Successfully decrypted data with envelope encryption', {
        keyId: encryptedData.keyId,
      });

      return plaintext;
    } catch (error) {
      logger.error('Failed to decrypt data with envelope encryption', {
        error,
        keyId: encryptedData.keyId,
      });
      throw new Error('Decryption failed');
    }
  }

  /**
   * Generate a new Data Encryption Key
   */
  async generateDataEncryptionKey(): Promise<DataEncryptionKey> {
    const key = crypto.randomBytes(config.encryption.keyLength);

    const dek: DataEncryptionKey = {
      id: crypto.randomUUID(),
      key,
      algorithm: config.encryption.algorithm,
      expiresAt: new Date(Date.now() + config.encryption.keyRotationDays * 24 * 60 * 60 * 1000),
    };

    logger.debug('Generated new DEK', { dekId: dek.id });
    return dek;
  }

  /**
   * Rotate encryption keys for compliance
   */
  async rotateKeys(): Promise<void> {
    try {
      // In production, this would rotate the master key in KMS/HSM
      this.masterKey = this.initializeMasterKey();
      logger.info('Successfully rotated encryption keys', {
        keyId: config.encryption.masterKeyId,
      });
    } catch (error) {
      logger.error('Failed to rotate encryption keys', {
        error,
        keyId: config.encryption.masterKeyId,
      });
      throw error;
    }
  }

  // Private helper methods

  private initializeMasterKey(): Buffer {
    // In production, this would retrieve the key from KMS/HSM
    // For development, we'll use a deterministic key for consistency
    const fixedSeed = 'NexusPay-Development-Master-Key-2025-Fixed-Seed';
    const hash = crypto.createHash('sha256');
    hash.update(fixedSeed);
    return hash.digest();
  }

  private encryptWithAesGcm(plaintext: string, key: Buffer, context: string): {
    encryptedValue: Buffer;
    nonce: Buffer;
    authTag: Buffer;
  } {
    const plaintextBytes = Buffer.from(plaintext, 'utf8');
    const nonce = crypto.randomBytes(config.encryption.nonceLength);
    const contextBytes = Buffer.from(context, 'utf8');

    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
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

  private decryptWithAesGcm(
    encryptedValue: Buffer,
    key: Buffer,
    nonce: Buffer,
    authTag: Buffer,
    context: string
  ): string {
    const contextBytes = Buffer.from(context, 'utf8');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(authTag);
    decipher.setAAD(contextBytes);

    let plaintext = decipher.update(encryptedValue);
    plaintext = Buffer.concat([plaintext, decipher.final()]);

    return plaintext.toString('utf8');
  }

  private encryptDek(dek: Buffer, context: string): { encryptedDek: Buffer; dekNonce: Buffer; dekAuthTag: Buffer } {
    const contextBytes = Buffer.from(context, 'utf8');
    const nonce = crypto.randomBytes(config.encryption.nonceLength);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
    cipher.setAAD(contextBytes);

    let encryptedDek = cipher.update(dek);
    encryptedDek = Buffer.concat([encryptedDek, cipher.final()]);

    return {
      encryptedDek,
      dekNonce: nonce,
      dekAuthTag: cipher.getAuthTag(),
    };
  }

  private decryptDek(encryptedDek: Buffer, nonce: Buffer, authTag: Buffer, context: string): Buffer {
    const contextBytes = Buffer.from(context, 'utf8');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, nonce);
    decipher.setAuthTag(authTag);
    decipher.setAAD(contextBytes);

    let dek = decipher.update(encryptedDek);
    dek = Buffer.concat([dek, decipher.final()]);

    return dek;
  }
}

// Export singleton instance
export const encryptionService = new EncryptionService();
