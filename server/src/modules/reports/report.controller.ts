import type { Request, Response } from 'express';
import { catchAsync } from '../../lib/catchAsync.js';
import { AppError } from '../../lib/AppError.js';
import { generateInvestigationReport, generateAlertReport } from './report.service.js';

export const getInvestigationReport = catchAsync(async (req: Request, res: Response) => {
  const investigation_id = String(req.params.investigation_id || '');
  if (!investigation_id) {
    throw new AppError('investigation_id is required', 400);
  }

  const report = await generateInvestigationReport(investigation_id);
  res.status(200).json({ success: true, report });
});

export const getAlertReport = catchAsync(async (req: Request, res: Response) => {
  const alert_id = String(req.params.alert_id || '');
  if (!alert_id) {
    throw new AppError('alert_id is required', 400);
  }

  const report = await generateAlertReport(alert_id);
  res.status(200).json({ success: true, report });
});
