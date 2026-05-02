import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { AppError } from '../lib/AppError.js';
import { logger } from '../lib/logger.js';

// Webhook verification middleware for Rapid7 webhooks
export const verifyWebhookSignature = (req: Request, res: Response, next: NextFunction) => {
  try {
    const signature = req.headers['x-rapid7-signature'] as string;
    const webhookSecret = process.env.RAPID7_WEBHOOK_SECRET || 'default-secret';

    if (!signature) {
      logger.warn('Webhook request missing signature header');
      throw new AppError('Webhook signature missing', 401);
    }

    // Reconstruct the request body as raw JSON string for signature verification
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);

    // Create HMAC SHA256 signature
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(rawBody)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      logger.warn('Webhook signature verification failed');
      throw new AppError('Webhook signature invalid', 403);
    }

    logger.info('Webhook signature verified successfully');
    next();
  } catch (err: any) {
    if (err instanceof AppError) {
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
      });
    }
    logger.error('Webhook verification error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Webhook verification failed',
    });
  }
};
