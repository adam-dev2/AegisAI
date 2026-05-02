import type { Request, Response } from 'express';
import { catchAsync } from '../../lib/catchAsync.js';
import { AppError } from '../../lib/AppError.js';
import { fetchAlerts, fetchAlertById, updateAlertStatus } from './alerts.service.js';

export const getAlerts = catchAsync(async (req: Request, res: Response) => {
  const investigationId = req.query.investigation_id as string | undefined;
  const limit = Number(req.query.limit) || 50;

  const alerts = await fetchAlerts(investigationId, limit);
  res.status(200).json({
    success: true,
    investigation_id: investigationId || null,
    total: alerts.length,
    alerts,
  });
});

export const getAlert = catchAsync(async (req: Request, res: Response) => {
  const alertId = String(req.params.alertId || '');
  if (!alertId) {
    throw new AppError('alertId is required', 400);
  }

  const alert = await fetchAlertById(alertId);
  res.status(200).json({ success: true, alert });
});

export const patchAlertStatus = catchAsync(async (req: Request, res: Response) => {
  const alertId = String(req.params.alertId || '');
  const { status } = req.body;

  if (!alertId) {
    throw new AppError('alertId is required', 400);
  }
  if (!status || typeof status !== 'string') {
    throw new AppError('status is required and must be a string', 400);
  }

  const updated = await updateAlertStatus(alertId, status);
  res.status(200).json({ success: true, alert: updated });
});
