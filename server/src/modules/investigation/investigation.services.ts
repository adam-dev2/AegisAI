import pLimit from 'p-limit';
import { logger } from '../../lib/logger.js';
import { parseInvestigationDetails } from '../../tools/parseInvestigation.js';
import { rapid7ClientEvidence, rapid7ClientVersion2 } from '../siem/rapid7.client.js';
import fs from 'fs'

const limit = pLimit(5);

export const processInvestigation = async (investigaions:any[]) => {
    logger.info("I'm in Processing Investigation")
    const results = await Promise.allSettled(
        investigaions.map(investigation =>
            limit(() => processSingleInvestigation(investigation))
        )
    );
    for (const r of results) {
        if (r.status === "rejected") {
        console.error("Failed:", r.reason);
        }
    }
}

// Single Investigation
const processSingleInvestigation = async (rawInv: any) => {
    const parsed = parseInvestigationDetails(rawInv);
    logger.info(`Processing investigation ID: ${parsed.id}`);

    const [detailsRes, alertsRes] = await Promise.all([
        rapid7ClientVersion2.get(`/investigations/${parsed.id}`),
        rapid7ClientVersion2.get(`/investigations/${parsed.id}/alerts`)
    ]);

    const alertsData = alertsRes.data?.data || [];

    const evidences = await Promise.all(
        alertsData.map(async (alert: any) => {
            try {
                const evidenceRes = await rapid7ClientEvidence.get(`/alerts/${alert.id}/evidences`);

                return {
                    alertId: alert.id,
                    evidence: parseEvidenceDetails(evidenceRes.data.evidences)
                };
            } catch (err: any) {
                logger.warn(`Failed to fetch evidence for alert ${alert.id}: ${err.message}`);
                return {
                    alertid: alert.id,
                    evidence: []
                };
            }
        })
    );
    const context = {
        investigationId: parsed.id,
        alerts: alertsData,
        details: detailsRes.data,
        evidences: evidences
    };

    fs.writeFileSync(
        `context-${parsed.id}.json`, 
        JSON.stringify(context, null, 2)
    );

    logger.info(`[CONTEXT] Saved for investigation ${parsed.id}`);
    return context;
};


// Parsing Evidence details
const parseEvidenceDetails = (evidences:any) => {
    const parsed = evidences.map((evi:any) => {
        return {
            rrn:evi.rrn,
            created_at:evi.created_at,
            evented_at:evi.evented_at,
            updated_at:evi.updated_at,
            event_type:evi.event_type,
            data:(evi.data.length === 0)?{}:JSON.parse(evi.data),
            association_reasons:evi.association_reasons,
            log_details:evi.log_details
        }
    })

    return parsed
}

