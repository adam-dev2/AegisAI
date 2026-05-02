import { logger } from '../../lib/logger.js';
import { jobQueue } from '../../config/queue.js';

export interface RapidWebhookPayload {
  type: 'investigation.created' | 'investigation.updated' | 'alert.created' | 'investigation.completed';
  investigation_id?: string;
  alert_id?: string;
  timestamp: string;
  data: any;
}

export async function handleWebhookEvent(payload: RapidWebhookPayload): Promise<void> {
  const { type, investigation_id, alert_id, timestamp, data } = payload;

  logger.info(`Processing webhook event: ${type}`, { investigation_id, alert_id });

  try {
    switch (type) {
      case 'investigation.created':
        await handleInvestigationCreated(investigation_id, data);
        break;

      case 'investigation.updated':
        await handleInvestigationUpdated(investigation_id, data);
        break;

      case 'alert.created':
        await handleAlertCreated(alert_id, investigation_id, data);
        break;

      case 'investigation.completed':
        await handleInvestigationCompleted(investigation_id, data);
        break;

      default:
        logger.warn(`Unknown webhook event type: ${type}`);
    }

    logger.info(`Webhook event processed successfully: ${type}`);
  } catch (err: any) {
    logger.error(`Webhook event processing failed for ${type}:`, err.message);
    throw err;
  }
}

async function handleInvestigationCreated(investigationId: string | undefined, data: any): Promise<void> {
  if (!investigationId) {
    throw new Error('Investigation ID required for investigation.created event');
  }

  logger.info(`Investigation created: ${investigationId}`);

  // Queue investigation job for processing
  const jobId = await jobQueue.add('investigation', {
    investigation_id: investigationId,
    event: 'created',
  });

  logger.info(`Queued investigation job: ${jobId}`);
}

async function handleInvestigationUpdated(investigationId: string | undefined, data: any): Promise<void> {
  if (!investigationId) {
    throw new Error('Investigation ID required for investigation.updated event');
  }

  logger.info(`Investigation updated: ${investigationId}`, { status: data?.status });

  // Queue investigation job for re-processing
  const jobId = await jobQueue.add('investigation', {
    investigation_id: investigationId,
    event: 'updated',
  });

  logger.info(`Queued investigation update job: ${jobId}`);
}

async function handleAlertCreated(alertId: string | undefined, investigationId: string | undefined, data: any): Promise<void> {
  if (!alertId) {
    throw new Error('Alert ID required for alert.created event');
  }

  logger.info(`Alert created: ${alertId} (Investigation: ${investigationId})`);

  // Queue notification job
  const jobId = await jobQueue.add('notification', {
    alert_id: alertId,
    investigation_id: investigationId,
    notification_type: 'alert_created',
    payload: {
      alert_type: data?.alert_type,
      severity: data?.severity,
    },
  });

  logger.info(`Queued alert notification job: ${jobId}`);
}

async function handleInvestigationCompleted(investigationId: string | undefined, data: any): Promise<void> {
  if (!investigationId) {
    throw new Error('Investigation ID required for investigation.completed event');
  }

  logger.info(`Investigation completed: ${investigationId}`);

  // Queue enrichment and report generation
  const enrichJobId = await jobQueue.add('enrichment', {
    investigation_id: investigationId,
  });

  const notificationJobId = await jobQueue.add('notification', {
    investigation_id: investigationId,
    notification_type: 'investigation_completed',
    payload: {
      status: data?.status,
      alerts_count: data?.alerts_count,
    },
  });

  logger.info(`Queued enrichment job: ${enrichJobId}, notification job: ${notificationJobId}`);
}
