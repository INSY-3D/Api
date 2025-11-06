import { Router } from 'express';
import { adminController } from '@/controllers/admin.controller';
import { authenticateToken, requireAdmin } from '@/middleware/auth.middleware';
import { validateRequest, validateQuery, validateParams } from '@/middleware/validation.middleware';
import { z } from 'zod';

const router = Router();

const createStaffSchema = z.object({
  fullName: z.string().regex(/^[A-Za-z ,.'-]{2,}$/),
  staffId: z.string().regex(/^[A-Z0-9-]{3,20}$/),
  email: z.string().email(),
  password: z.string().min(8).optional(),
});

const updateStaffSchema = z.object({
  fullName: z.string().regex(/^[A-Za-z ,.'-]{2,}$/).optional(),
  email: z.string().email().optional(),
  isActive: z.boolean().optional(),
  password: z.string().min(8).optional(),
});

const listQuerySchema = z.object({
  q: z.string().regex(/^[A-Za-z0-9@._-]{0,64}$/).optional(),
  status: z.enum(['active','inactive']).optional(),
  page: z.coerce.number().min(1).max(1000).optional(),
});

const idParamSchema = z.object({ id: z.string().min(1) });

router.get('/admin/staff', authenticateToken, requireAdmin, validateQuery(listQuerySchema), adminController.listStaff.bind(adminController));
router.post('/admin/staff', authenticateToken, requireAdmin, validateRequest(createStaffSchema), adminController.createStaff.bind(adminController));
router.patch('/admin/staff/:id', authenticateToken, requireAdmin, validateParams(idParamSchema), validateRequest(updateStaffSchema), adminController.updateStaff.bind(adminController));
router.delete('/admin/staff/:id', authenticateToken, requireAdmin, validateParams(idParamSchema), adminController.deleteStaff.bind(adminController));

export default router;


