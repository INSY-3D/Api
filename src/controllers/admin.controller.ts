import { Request, Response } from 'express';
import { logger } from '@/config/logger';
import { adminService } from '@/services/admin.service';

export class AdminController {
  async listStaff(req: Request, res: Response): Promise<void> {
    try {
      const { q, status, page = '1' } = req.query as Record<string, string>;
      const result = await adminService.listStaff({ q, status, page: parseInt(page || '1', 10) });
      res.status(200).json({ success: true, data: result });
    } catch (error) {
      logger.error('List staff failed', { error });
      res.status(500).json({ success: false, message: 'Failed to list staff', code: 'LIST_STAFF_FAILED' });
    }
  }

  async createStaff(req: Request, res: Response): Promise<void> {
    try {
      const { fullName, staffId, email, password } = req.body;
      const result = await adminService.createStaff({ fullName, staffId, email, password });
      res.status(201).json({ success: true, message: 'Staff created', data: result });
    } catch (error) {
      logger.error('Create staff failed', { error });
      res.status(400).json({ success: false, message: (error as Error).message || 'Failed to create staff', code: 'CREATE_STAFF_FAILED' });
    }
  }

  async updateStaff(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params as { id: string };
      const { fullName, email, isActive, password } = req.body;
      const result = await adminService.updateStaff(id, { fullName, email, isActive, password });
      res.status(200).json({ success: true, message: 'Staff updated', data: result });
    } catch (error) {
      logger.error('Update staff failed', { error });
      res.status(400).json({ success: false, message: (error as Error).message || 'Failed to update staff', code: 'UPDATE_STAFF_FAILED' });
    }
  }

  async deleteStaff(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params as { id: string };
      await adminService.deleteStaff(id);
      res.status(200).json({ success: true, message: 'Staff deleted' });
    } catch (error) {
      logger.error('Delete staff failed', { error });
      res.status(400).json({ success: false, message: (error as Error).message || 'Failed to delete staff', code: 'DELETE_STAFF_FAILED' });
    }
  }
}

export const adminController = new AdminController();


