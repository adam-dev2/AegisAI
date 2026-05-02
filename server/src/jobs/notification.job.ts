import { logger } from '../lib/logger.js';

export interface NotificationJobData {
  investigation_id: string;
  recipient_email?: string;
  notification_type: 'alert_created' | 'investigation_completed' | 'report_ready';
  payload?: any;
}

export async function handleNotificationJob(jobData: NotificationJobData) {
  const { investigation_id, recipient_email, notification_type, payload } = jobData;
  logger.info(`Processing notification job for ${investigation_id}`, { type: notification_type });

  try {
    // TODO: Implement actual email/push notification logic using your provider
    // This is a placeholder that just logs for now

    const message = formatNotificationMessage(notification_type, payload);

    if (recipient_email) {
      logger.info(`[NOTIFICATION] To: ${recipient_email}, Type: ${notification_type}, Message: ${message}`);
      // TODO: Send email via nodemailer, SendGrid, or similar
      // await sendEmail(recipient_email, subject, html);
    } else {
      logger.info(`[NOTIFICATION] No recipient; skipping email. Message: ${message}`);
    }

    logger.info(`Notification job completed for ${investigation_id}`);
    return { success: true, investigation_id, notification_type };
  } catch (err: any) {
    logger.error(`Notification job failed for ${investigation_id}:`, err.message);
    throw err;
  }
}

function formatNotificationMessage(type: string, payload: any): string {
  switch (type) {
    case 'alert_created':
      return `New alert created: ${payload?.alert_type ?? 'unknown'}`;
    case 'investigation_completed':
      return `Investigation ${payload?.investigation_id ?? 'unknown'} processing completed`;
    case 'report_ready':
      return `Report ready for investigation ${payload?.investigation_id ?? 'unknown'}`;
    default:
      return `Notification: ${type}`;
  }
}
