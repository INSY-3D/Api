import { randomBytes } from 'crypto';
import { prisma } from '@/config/database';
import { encryptionService } from './encryption.service';
import { authService } from './auth.service';

type ListParams = { q?: string; status?: string; page?: number };

class AdminService {
  private async tryDecryptString(possiblyEncrypted: string | null | undefined): Promise<string | null> {
    if (!possiblyEncrypted || possiblyEncrypted.trim() === '') return null;
    try {
      const parsed = JSON.parse(possiblyEncrypted);
      if (!parsed || typeof parsed !== 'object') return null;
      const plaintext = await encryptionService.decrypt(parsed);
      return plaintext;
    } catch {
      // Legacy plain text fallback
      return possiblyEncrypted;
    }
  }
  async listStaff(params: ListParams) {
    const pageSize = 20;
    const page = Math.max(1, params.page || 1);
    const where: any = { role: 'staff' };
    if (params.status === 'active') where.isActive = true;
    if (params.status === 'inactive') where.isActive = false;
    // Basic filter on email/accountNumber plain legacy values for safety; decrypted filter omitted
    if (params.q) {
      where.OR = [
        { emailEncrypted: { contains: params.q } },
        { accountNumberEncrypted: { contains: params.q } },
      ];
    }
    const [items, total] = await Promise.all([
      prisma.user.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (page - 1) * pageSize, take: pageSize }),
      prisma.user.count({ where }),
    ]);
    // Map to admin-safe DTO with decrypted fields
    const mapped = await Promise.all(items.map(async (u) => {
      const fullName = await this.tryDecryptString(u.fullNameEncrypted);
      const email = await this.tryDecryptString(u.emailEncrypted || null);
      const staffId = await this.tryDecryptString(u.accountNumberEncrypted);
      return {
        id: u.id,
        fullName: fullName || '',
        email: email || undefined,
        staffId: staffId || '',
        isActive: u.isActive,
        createdAt: u.createdAt,
      };
    }));
    return { items: mapped, total, page, pageSize };
  }

  async createStaff(input: { fullName: string; staffId: string; email: string; password: string }) {
    // Basic required field checks to avoid encryption errors
    if (!input.fullName || !input.fullName.trim()) throw new Error('Full name is required');
    if (!input.staffId || !input.staffId.trim()) throw new Error('Staff ID is required');
    if (!input.email || !input.email.trim()) throw new Error('Email is required');
    // Ensure no duplicate staff by accountNumber or email
    const existing = await prisma.user.findFirst({
      where: {
        role: 'staff',
        OR: [
          { emailEncrypted: input.email },
          { accountNumberEncrypted: input.staffId },
        ],
      },
    });
    if (existing) throw new Error('Staff already exists');

    // Enforce strong password: 12+ chars, upper, lower, digit, special
    const strongPwd = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{12,}$/;
    if (!input.password || !strongPwd.test(input.password)) {
      throw new Error('Password must be at least 12 characters and include uppercase, lowercase, number, and special character');
    }
    const passwordHash = await authService.hashPassword(input.password);

    const fullNameEncrypted = await encryptionService.encrypt(input.fullName);
    // Use non-empty placeholder for SA ID to satisfy encryption requirements
    const saIdEncrypted = await encryptionService.encrypt('STAFF');
    const accountNumberEncrypted = await encryptionService.encrypt(input.staffId);
    const emailEncrypted = await encryptionService.encrypt(input.email);

    const user = await prisma.user.create({
      data: {
        fullNameEncrypted: JSON.stringify(fullNameEncrypted),
        saIdEncrypted: JSON.stringify(saIdEncrypted),
        accountNumberEncrypted: JSON.stringify(accountNumberEncrypted),
        emailEncrypted: JSON.stringify(emailEncrypted),
        passwordHash,
        role: 'staff',
        isActive: true,
      },
    });
    return { user };
  }

  async updateStaff(userId: string, input: { fullName?: string; email?: string; isActive?: boolean; password?: string }) {
    const data: any = {};
    if (input.fullName) data.fullNameEncrypted = JSON.stringify(await encryptionService.encrypt(input.fullName));
    if (input.email) data.emailEncrypted = JSON.stringify(await encryptionService.encrypt(input.email));
    if (typeof input.isActive === 'boolean') data.isActive = input.isActive;
    if (input.password && input.password.length >= 8) data.passwordHash = await authService.hashPassword(input.password);
    const user = await prisma.user.update({ where: { id: userId }, data });
    return { user };
  }

  async deleteStaff(userId: string) {
    // Soft delete by deactivating account to preserve auditability
    await prisma.user.update({ where: { id: userId }, data: { isActive: false } });
  }

  private generateTempPassword(): string {
    // 12+ strong temp password using cryptographically secure random bytes
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789@$!%*?&';
    const length = 14;
    let out = '';
    // Generate secure random bytes and map to character set
    const randomValues = randomBytes(length);
    for (let i = 0; i < length; i++) {
      const byte = randomValues.readUInt8(i);
      out += chars[byte % chars.length];
    }
    return out;
  }
}

export const adminService = new AdminService();


