import { EncryptedData, DataEncryptionKey } from '@/types';
export declare class EncryptionService {
    private masterKey;
    constructor();
    encrypt(plaintext: string, context?: string): Promise<EncryptedData>;
    decrypt(encryptedData: EncryptedData): Promise<string>;
    generateDataEncryptionKey(): Promise<DataEncryptionKey>;
    rotateKeys(): Promise<void>;
    private initializeMasterKey;
    private encryptWithAesGcm;
    private decryptWithAesGcm;
    private encryptDek;
    private decryptDek;
}
export declare const encryptionService: EncryptionService;
//# sourceMappingURL=encryption.service.d.ts.map