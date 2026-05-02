import { logger } from '../lib/logger.js';
import { enrichInvestigation } from '../modules/investigation/enrichment.service.js';
import fs from 'fs';
import path from 'path';

export interface EnrichmentJobData {
  investigation_id: string;
}

export async function handleEnrichmentJob(jobData: EnrichmentJobData) {
  const { investigation_id } = jobData;
  logger.info(`Processing enrichment job for investigation ${investigation_id}`);

  try {
    const filePath = path.resolve(process.cwd(), `context-${investigation_id}.json`);

    if (!fs.existsSync(filePath)) {
      throw new Error(`Context file not found for ${investigation_id}`);
    }

    const raw = await fs.promises.readFile(filePath, 'utf8');
    const context = JSON.parse(raw);

    const enrichment = await enrichInvestigation(investigation_id, context);

    logger.info(`Enrichment job completed for ${investigation_id}`, { enrichment });
    return { success: true, enrichment };
  } catch (err: any) {
    logger.error(`Enrichment job failed for ${investigation_id}:`, err.message);
    throw err;
  }
}
