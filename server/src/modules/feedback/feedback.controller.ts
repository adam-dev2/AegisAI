import type { Request, Response } from 'express';
import { catchAsync } from '../../lib/catchAsync.js';
import { AppError } from '../../lib/AppError.js';
import { submitFeedback, getFeedbackByInvestigation, getFeedbackStats as fetchFeedbackStats } from './feedback.service.js';

export const postFeedback = catchAsync(async (req: Request, res: Response) => {
  const { investigation_id, rating, comment } = req.body;
  const userId = req.user?.id;

  if (!userId) {
    throw new AppError('Unauthorized', 403);
  }

  if (!investigation_id || !rating) {
    throw new AppError('investigation_id and rating are required', 400);
  }

  const ratingNum = Number(rating) as 1 | 2 | 3 | 4 | 5;
  if (typeof rating !== 'number' || ratingNum < 1 || ratingNum > 5) {
    throw new AppError('rating must be between 1 and 5', 400);
  }

  const feedback = await submitFeedback(userId, {
    investigation_id,
    rating: ratingNum,
    comment,
  });

  res.status(201).json({
    success: true,
    message: 'feedback submitted',
    feedback,
  });
});

export const getFeedback = catchAsync(async (req: Request, res: Response) => {
  const investigationId = String(req.params.investigation_id || '');

  if (!investigationId) {
    throw new AppError('investigation_id is required', 400);
  }

  const feedback = await getFeedbackByInvestigation(investigationId);

  res.status(200).json({
    success: true,
    investigation_id: investigationId,
    total: feedback.length,
    feedback,
  });
});

export const getFeedbackStats = catchAsync(async (req: Request, res: Response) => {
  const investigationId = String(req.params.investigation_id || '');

  if (!investigationId) {
    throw new AppError('investigation_id is required', 400);
  }

  const stats = await fetchFeedbackStats(investigationId);

  res.status(200).json({
    success: true,
    investigation_id: investigationId,
    stats,
  });
});
