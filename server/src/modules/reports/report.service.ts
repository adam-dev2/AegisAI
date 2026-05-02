import fs from 'fs';
import path from 'path';
import { rapid7ClientVersion2, rapid7ClientEvidence } from '../siem/rapid7.client.js';

export async function generateInvestigationReport(investigationId: string) {
  const filePath = path.resolve(process.cwd(), `context-${investigationId}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Investigation context file not found for ${investigationId}`);
  }

  const raw = await fs.promises.readFile(filePath, 'utf8');
  const context = JSON.parse(raw);

  return {
    investigation_id: investigationId,
    summary: {
      title: context.details?.title ?? context.details?.InvestigationName ?? 'unknown',
      created_time: context.details?.created_time ?? context.details?.created_at ?? null,
      total_alerts: context.pipeline_meta?.total_alerts ?? context.alerts?.length ?? 0,
      processed_alerts: context.alerts?.length ?? 0,
    },
    top_alerts: (context.alerts ?? []).slice(0, 5).map((alert: any) => ({
      alert_id: alert.alert_id,
      alert_type: alert.alert_type,
      alert_source: alert.alert_source,
      created_time: alert.created_time,
      fetch_status: alert.fetch_status,
      evidence_count: Array.isArray(alert.evidences) ? alert.evidences.length : 0,
    })),
  };
}

export async function generateAlertReport(alertId: string) {
  const alertRes = await rapid7ClientVersion2.get(`/alerts/${encodeURIComponent(alertId)}`);
  const evidenceRes = await rapid7ClientEvidence.get(`/alerts/${encodeURIComponent(alertId)}/evidences`);

  return {
    alert_id: alertId,
    alert: alertRes.data,
    evidences: evidenceRes.data?.evidences ?? [],
  };
}
