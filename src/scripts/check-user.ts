import { PrismaClient } from '@prisma/client';
import { encryptionService } from '../services/encryption.service';
import { logger } from '../config/logger';

const prisma = new PrismaClient();

async function tryDecrypt(possiblyEncrypted: string | null): Promise<string | null> {
  if (!possiblyEncrypted || possiblyEncrypted.trim() === '') return null;
  try {
    const parsed = JSON.parse(possiblyEncrypted);
    if (!parsed || typeof parsed !== 'object') return null;
    return await encryptionService.decrypt(parsed);
  } catch (error) {
    if (typeof possiblyEncrypted === 'string' && possiblyEncrypted.length > 0) {
      return possiblyEncrypted;
    }
    return null;
  }
}

async function checkUser() {
  try {
    logger.info('Checking all users in database...');

    const users = await prisma.user.findMany();

    console.log('\n=== DATABASE USERS ===\n');
    
    for (const user of users) {
      const saId = await tryDecrypt(user.saIdEncrypted);
      const accountNumber = await tryDecrypt(user.accountNumberEncrypted);
      const email = await tryDecrypt(user.emailEncrypted ?? null);
      const fullName = await tryDecrypt(user.fullNameEncrypted);

      console.log(`User ID: ${user.id}`);
      console.log(`  Full Name: ${fullName}`);
      console.log(`  SA ID: ${saId}`);
      console.log(`  Account Number: ${accountNumber}`);
      console.log(`  Email: ${email || '(none)'}`);
      console.log(`  Role: ${user.role}`);
      console.log(`  Active: ${user.isActive}`);
      console.log(`  Created: ${user.createdAt}`);
      console.log('---\n');
    }

    console.log(`\nTotal users: ${users.length}\n`);
  } catch (error) {
    logger.error('Check user failed', { error });
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

checkUser()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Process failed', { error });
    process.exit(1);
  });

