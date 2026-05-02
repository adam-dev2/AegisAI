import type { Request, Response } from 'express';
import { catchAsync } from '../../lib/catchAsync.js';
import { AppError } from '../../lib/AppError.js';
import {
  createSIEMConnection,
  fetchSIEMConnections,
  updateSIEMConnection,
} from './siem.service.js';

export const createConnection = catchAsync(async (req: Request, res: Response) => {
  const { region, apikey, console } = req.body;
  const userId = req.user?.id;

  if (!region || !apikey || !console) {
    throw new AppError('region, apikey and console are required', 400);
  }
  if (!userId) {
    throw new AppError('Unauthorized', 403);
  }

  const connection = await createSIEMConnection(userId, console, apikey, region);

  res.status(200).json({
    success: true,
    message: `added ${console} to the dashboard`,
    connection,
  });
});

export const fetchConnections = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user?.id;

  if (!userId) {
    throw new AppError('Unauthorized', 403);
  }

  const connections = await fetchSIEMConnections(userId);

  res.status(200).json({
    success: true,
    totalConnections: connections.length,
    connections,
  });
});

export const updateConnection = catchAsync(async (req: Request, res: Response) => {
  const { connectionId, apikey, provider, region, is_active } = req.body;
  const userId = req.user?.id;

  if (!connectionId) {
    throw new AppError('connectionId is required', 400);
  }
  if (!userId) {
    throw new AppError('Unauthorized', 403);
  }

  if (!apikey && !provider && !region && typeof is_active === 'undefined') {
    throw new AppError('No fields provided to update', 400);
  }

  const connection = await updateSIEMConnection(userId, connectionId, {
    apiKey: apikey,
    provider,
    region,
    is_active,
  });

  res.status(200).json({
    success: true,
    message: 'connection updated',
    connection,
  });
});
