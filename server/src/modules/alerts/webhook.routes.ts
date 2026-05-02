import express from 'express';
import { catchAsync } from '../../lib/catchAsync.js';
import { AppError } from '../../lib/AppError.js';
import { verifyWebhookSignature } from '../../middleware/webhook.verify.js';
import { handleWebhookEvent, type RapidWebhookPayload } from './webhook.handler.js';
import type { Request, Response } from 'express';

const router = express.Router();

// POST /api/v1/webhooks/rapid7
// Receives webhook events from Rapid7
router.post(
  '/rapid7',
  verifyWebhookSignature,
  catchAsync(async (req: Request, res: Response) => {
    const payload = req.body as RapidWebhookPayload;

    if (!payload.type) {
      throw new AppError('Webhook event type is required', 400);
    }

    if (!payload.timestamp) {
      throw new AppError('Webhook timestamp is required', 400);
    }

    // Process webhook asynchronously (don't wait for completion)
    handleWebhookEvent(payload).catch((err: any) => {
      console.error('Webhook processing error:', err.message);
    });

    // Return 202 Accepted immediately
    res.status(202).json({
      success: true,
      message: 'Webhook event accepted for processing',
    });
  })
);

export default router;
