"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const database_1 = require("../config/database");
const logger_1 = require("../config/logger");
async function main() {
    const keepEmails = new Set([
        'test@nexuspay.dev',
        'staff@nexuspay.dev',
    ]);
    const keepAccounts = new Set([
        '12345678',
        '87654321',
    ]);
    logger_1.logger.info('Starting cleanup: deleting users except demo accounts');
    const allUsers = await database_1.prisma.user.findMany({ select: { id: true } });
    const demoLinkedUserIdsSet = new Set();
    const demoPayments = await database_1.prisma.payment.findMany({
        where: { beneficiaryAccountNumber: { in: Array.from(keepAccounts) } },
        select: { userId: true }
    });
    demoPayments.forEach(p => demoLinkedUserIdsSet.add(p.userId));
    const demoBenefs = await database_1.prisma.beneficiary.findMany({
        where: { accountNumber: { in: Array.from(keepAccounts) } },
        select: { userId: true }
    });
    demoBenefs.forEach(b => demoLinkedUserIdsSet.add(b.userId));
    const usersToDelete = allUsers.filter(u => !demoLinkedUserIdsSet.has(u.id));
    if (usersToDelete.length === 0) {
        logger_1.logger.info('No users to delete. Cleanup complete.');
        return;
    }
    logger_1.logger.info(`Deleting ${usersToDelete.length} user(s) and related data`);
    const userIds = usersToDelete.map(u => u.id);
    await database_1.prisma.payment.deleteMany({ where: { userId: { in: userIds } } });
    await database_1.prisma.beneficiary.deleteMany({ where: { userId: { in: userIds } } });
    await database_1.prisma.userSession.deleteMany({ where: { userId: { in: userIds } } });
    const result = await database_1.prisma.user.deleteMany({ where: { id: { in: userIds } } });
    logger_1.logger.info(`Deleted ${result.count} user(s). Cleanup complete.`);
}
main()
    .catch((err) => {
    logger_1.logger.error('Cleanup failed', { error: err });
    process.exitCode = 1;
})
    .finally(async () => {
    await database_1.prisma.$disconnect();
});
//# sourceMappingURL=cleanup.js.map