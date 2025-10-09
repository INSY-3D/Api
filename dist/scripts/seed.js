"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const auth_service_1 = require("../services/auth.service");
const encryption_service_1 = require("../services/encryption.service");
const logger_1 = require("../config/logger");
const prisma = new client_1.PrismaClient();
async function seed() {
    try {
        logger_1.logger.info('Starting database seeding...');
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
            const existingUser = await prisma.user.findFirst({
                where: {
                    OR: [
                        { emailEncrypted: userData.email },
                        { accountNumberEncrypted: userData.accountNumber },
                    ],
                },
            });
            if (existingUser) {
                logger_1.logger.info(`User ${userData.email} already exists, skipping...`);
                continue;
            }
            const passwordHash = await auth_service_1.authService.hashPassword(userData.password);
            const fullNameEncrypted = await encryption_service_1.encryptionService.encrypt(userData.fullName);
            const saIdEncrypted = await encryption_service_1.encryptionService.encrypt(userData.saId);
            const accountNumberEncrypted = await encryption_service_1.encryptionService.encrypt(userData.accountNumber);
            const emailEncrypted = await encryption_service_1.encryptionService.encrypt(userData.email);
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
            logger_1.logger.info(`Created user: ${userData.email} (${userData.role})`);
        }
        const testUser = await prisma.user.findFirst();
        if (testUser) {
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
            logger_1.logger.info('Created sample payments for test user');
        }
        logger_1.logger.info('Database seeding completed successfully!');
    }
    catch (error) {
        logger_1.logger.error('Database seeding failed', { error });
        throw error;
    }
    finally {
        await prisma.$disconnect();
    }
}
seed()
    .then(() => {
    logger_1.logger.info('Seeding process completed');
    process.exit(0);
})
    .catch((error) => {
    logger_1.logger.error('Seeding process failed', { error });
    process.exit(1);
});
//# sourceMappingURL=seed.js.map