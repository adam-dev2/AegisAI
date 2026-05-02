import { logger } from '../lib/logger.js';
import { processInvestigation } from '../modules/investigation/investigation.services.js';
import { rapid7ClientVersion2 } from '../modules/siem/rapid7.client.js';

export interface InvestigationJobData {
  investigation_id: string;
  time_range?: string;
}

export async function handleInvestigationJob(jobData: InvestigationJobData) {
  const { investigation_id, time_range } = jobData;
  logger.info(`Processing investigation job for ${investigation_id}`);

  try {
    const response = await rapid7ClientVersion2.get(`/investigations/${investigation_id}`);
    const investigation = response.data;

    if (!investigation) {
      throw new Error(`Investigation ${investigation_id} not found`);
    }

    const result = await processInvestigation([investigation]);

    logger.info(`Investigation job completed for ${investigation_id}`, { alerts: result[0]?.alerts?.length ?? 0 });
    return { success: true, investigation_id, alerts_processed: result[0]?.alerts?.length ?? 0 };
  } catch (err: any) {
    logger.error(`Investigation job failed for ${investigation_id}:`, err.message);
    throw err;
  }
}
