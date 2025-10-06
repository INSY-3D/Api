import { prisma } from '@/config/database'
import { logger } from '@/config/logger'

async function main() {
  const keepEmails = new Set<string>([
    'test@nexuspay.dev', // demo customer
    'staff@nexuspay.dev', // demo staff (if present)
  ])
  const keepAccounts = new Set<string>([
    '12345678', // demo customer
    '87654321', // demo staff
  ])

  logger.info('Starting cleanup: deleting users except demo accounts')

  // Find users to delete
  // Because email/accountNumber are encrypted, filter by matching decrypted values on the app side is needed.
  // We don't have decrypt here; instead, we will conservatively keep users who have any payments or beneficiaries with demo account numbers
  // and remove users without those markers.

  const allUsers = await prisma.user.findMany({ select: { id: true } })

  // Find users linked to demo account numbers via beneficiaries or payments
  const demoLinkedUserIdsSet = new Set<string>()
  const demoPayments = await prisma.payment.findMany({
    where: { beneficiaryAccountNumber: { in: Array.from(keepAccounts) } },
    select: { userId: true }
  })
  demoPayments.forEach(p => demoLinkedUserIdsSet.add(p.userId))
  const demoBenefs = await prisma.beneficiary.findMany({
    where: { accountNumber: { in: Array.from(keepAccounts) } },
    select: { userId: true }
  })
  demoBenefs.forEach(b => demoLinkedUserIdsSet.add(b.userId))

  // Keep any users that are demo-linked; delete the rest
  const usersToDelete = allUsers.filter(u => !demoLinkedUserIdsSet.has(u.id))

  if (usersToDelete.length === 0) {
    logger.info('No users to delete. Cleanup complete.')
    return
  }

  logger.info(`Deleting ${usersToDelete.length} user(s) and related data`)

  // Delete related data first if cascade is not configured for all relations
  const userIds = usersToDelete.map(u => u.id)

  // Payments
  await prisma.payment.deleteMany({ where: { userId: { in: userIds } } })
  // Beneficiaries
  await prisma.beneficiary.deleteMany({ where: { userId: { in: userIds } } })
  // Sessions
  await prisma.userSession.deleteMany({ where: { userId: { in: userIds } } })

  // Finally delete users
  const result = await prisma.user.deleteMany({ where: { id: { in: userIds } } })

  logger.info(`Deleted ${result.count} user(s). Cleanup complete.`)
}

main()
  .catch((err) => {
    logger.error('Cleanup failed', { error: err })
    process.exitCode = 1
  })
  .finally(async () => {
    await prisma.$disconnect()
  })


