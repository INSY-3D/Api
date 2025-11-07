import { PrismaClient } from '@prisma/client';
import { authService } from '../services/auth.service';
import { encryptionService } from '../services/encryption.service';
import { logger } from '../config/logger';

const prisma = new PrismaClient();

// Task 2 Compliant: Database seeder with demo users
async function seed() {
  try {
    logger.info('Starting database seeding...');

    // Ensure single admin exists (exactly one)
    const existingAdmins = await prisma.user.findMany({ where: { role: 'admin' } });
    if (existingAdmins.length === 0) {
      const adminPasswordHash = await authService.hashPassword('AdminPass123!');
      const adminFullName = await encryptionService.encrypt('Admin User');
      const adminSaId = await encryptionService.encrypt('1122334455667');
      const adminAcc = await encryptionService.encrypt('11223344');
      const adminEmail = await encryptionService.encrypt('admin@nexuspay.dev');
      await prisma.user.create({
        data: {
          fullNameEncrypted: JSON.stringify(adminFullName),
          saIdEncrypted: JSON.stringify(adminSaId),
          accountNumberEncrypted: JSON.stringify(adminAcc),
          emailEncrypted: JSON.stringify(adminEmail),
          passwordHash: adminPasswordHash,
          role: 'admin',
          isActive: true,
        },
      });
      logger.info('Seeded single admin user (admin@nexuspay.dev)');
    } else if (existingAdmins.length > 1) {
      logger.warn('Multiple admins detected; leaving as-is to avoid data loss.');
    }

    // Create demo non-admin users
    const demoUsers = [
      {
        fullName: 'Test Customer',
        saId: '1234567890123',
        accountNumber: '12345678',
        email: 'test@nexuspay.dev',
        password: 'TestPass123!',
        role: 'customer',
      },
      {
        fullName: 'Staff Member',
        saId: '9876543210987',
        accountNumber: '87654321',
        email: 'staff@nexuspay.dev',
        password: 'StaffPass123!',
        role: 'staff',
      },
    ];

    for (const userData of demoUsers) {
      // Check if user already exists
      // Existing check needs to compare decrypted values; use plain-string fallback check first
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { emailEncrypted: userData.email }, // legacy plain value
            { accountNumberEncrypted: userData.accountNumber }, // legacy plain value
          ],
        },
      });

      if (existingUser) {
        logger.info(`User ${userData.email} already exists, skipping...`);
        continue;
      }

      // Hash password
      const passwordHash = await authService.hashPassword(userData.password);

      // Encrypt PII data
      const fullNameEncrypted = await encryptionService.encrypt(userData.fullName);
      const saIdEncrypted = await encryptionService.encrypt(userData.saId);
      const accountNumberEncrypted = await encryptionService.encrypt(userData.accountNumber);
      const emailEncrypted = await encryptionService.encrypt(userData.email);

      // Create user
      const user = await prisma.user.create({
        data: {
          fullNameEncrypted: JSON.stringify(fullNameEncrypted),
          saIdEncrypted: JSON.stringify(saIdEncrypted),
          accountNumberEncrypted: JSON.stringify(accountNumberEncrypted),
          emailEncrypted: JSON.stringify(emailEncrypted),
          passwordHash,
          role: userData.role,
          isActive: true,
        },
      });

      logger.info(`Created user: ${userData.email} (${userData.role})`);
    }

    // Create some sample payments
    const testUser = await prisma.user.findFirst();

    if (testUser) {
      // Create sample DRAFT payment (skip if already seeded)
      const p1Key = 'demo-payment-1';
      const existingP1 = await prisma.payment.findUnique({ where: { idempotencyKey: p1Key } });
      if (!existingP1) {
        await prisma.payment.create({
          data: {
            userId: testUser.id,
            amount: 1000.00,
            currency: 'USD',
            provider: 'SWIFT',
            idempotencyKey: p1Key,
            status: 'draft',
          },
        });
      }

      // Create sample PENDING_VERIFICATION payment (skip if already seeded)
      const p2Key = 'demo-payment-2';
      const existingP2 = await prisma.payment.findUnique({ where: { idempotencyKey: p2Key } });
      if (!existingP2) {
        await prisma.payment.create({
          data: {
            userId: testUser.id,
            amount: 2500.00,
            currency: 'EUR',
            provider: 'SWIFT',
            idempotencyKey: p2Key,
            status: 'pending_verification',
            beneficiaryName: 'John Doe',
            beneficiaryAccountNumber: '987654321',
            swiftCode: 'CHASUS33XXX',
            bankAddress: '123 Main St',
            bankCity: 'New York',
            bankPostalCode: '10001',
            bankCountry: 'US',
            reference: 'PAY-2025-001',
            purpose: 'Business payment',
          },
        });
      }

      logger.info('Created sample payments for test user');
    }

    logger.info('Database seeding completed successfully!');
  } catch (error) {
    logger.error('Database seeding failed', { error });
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run seeder
seed()
  .then(() => {
    logger.info('Seeding process completed');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Seeding process failed', { error });
    process.exit(1);
  });
