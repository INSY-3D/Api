import { PrismaClient } from '@prisma/client';
import { authService } from '../services/auth.service';
import { encryptionService } from '../services/encryption.service';
import { logger } from '../config/logger';

const prisma = new PrismaClient();

// Task 2 Compliant: Database seeder with demo users
async function seed() {
  try {
    logger.info('Starting database seeding...');

    // Create demo users
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
      {
        fullName: 'Admin User',
        saId: '1122334455667',
        accountNumber: '11223344',
        email: 'admin@nexuspay.dev',
        password: 'AdminPass123!',
        role: 'admin',
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
      // Create sample DRAFT payment
      await prisma.payment.create({
        data: {
          userId: testUser.id,
          amount: 1000.00,
          currency: 'USD',
          provider: 'SWIFT',
          idempotencyKey: 'demo-payment-1',
          status: 'draft',
        },
      });

      // Create sample PENDING_VERIFICATION payment
      await prisma.payment.create({
        data: {
          userId: testUser.id,
          amount: 2500.00,
          currency: 'EUR',
          provider: 'SWIFT',
          idempotencyKey: 'demo-payment-2',
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
