import fs from 'fs';
import path from 'path';
import { logger } from '../../lib/logger.js';
import type { EnrichedInvestigation } from '../investigation/investigation.services.js';

export async function generateFullReport(investigationId: string): Promise<any> {
  const filePath = path.resolve(process.cwd(), `context-${investigationId}.json`);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Investigation context not found for ${investigationId}`);
  }

  const raw = await fs.promises.readFile(filePath, 'utf8');
  const context: EnrichedInvestigation = JSON.parse(raw);

  const reportDate = new Date().toISOString();
  const alertSummary = context.alerts.reduce(
    (acc: Record<string, number>, alert: any) => {
      acc[alert.alert_type] = (acc[alert.alert_type] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const actorSummary: Record<string, Set<string>> = {
    users: new Set<string>(),
    ips: new Set<string>(),
    assets: new Set<string>(),
  };

  context.alerts?.forEach((alert: any) => {
    alert.evidences?.forEach((evidence: any) => {
      if (evidence.actor?.user) actorSummary.users?.add(evidence.actor.user);
      if (evidence.actor?.ip) actorSummary.ips?.add(evidence.actor.ip);
      if (evidence.actor?.asset) actorSummary.assets?.add(evidence.actor.asset);
    });
  });

  return {
    report_id: `rpt-${investigationId}-${Date.now()}`,
    investigation_id: investigationId,
    report_date: reportDate,
    investigation_details: {
      title: context.details?.title ?? 'unknown',
      created_time: context.details?.created_time ?? null,
      status: context.details?.status ?? 'unknown',
    },
    summary: {
      total_alerts_processed: context.pipeline_meta.alerts_fetched,
      total_evidence_items: context.alerts.reduce((sum, a) => sum + a.evidences.length, 0),
      fetch_failures: context.pipeline_meta.evidence_failures.length,
    },
    alert_breakdown: alertSummary,
    actors_involved: {
      unique_users: Array.from(actorSummary.users || []),
      unique_ips: Array.from(actorSummary.ips || []),
      unique_assets: Array.from(actorSummary.assets || []),
    },
    top_events: context.alerts
      .slice(0, 3)
      .map((alert) => ({
        alert_id: alert.alert_id,
        type: alert.alert_type,
        created_time: alert.created_time,
        evidence_count: alert.evidences.length,
      })),
  };
}

export async function saveReportToFile(investigationId: string, report: any): Promise<string> {
  const fileName = `report-${investigationId}-${Date.now()}.json`;
  const filePath = path.resolve(process.cwd(), 'reports', fileName);

  const reportsDir = path.dirname(filePath);
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  await fs.promises.writeFile(filePath, JSON.stringify(report, null, 2), 'utf8');
  logger.info(`Report saved: ${filePath}`);

  return filePath;
}
