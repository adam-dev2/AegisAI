import pLimit from 'p-limit';
import { logger } from '../../lib/logger.js';
import { parseInvestigationDetails } from '../../tools/parseInvestigation.js';
import { rapid7ClientEvidence, rapid7ClientVersion2 } from '../siem/rapid7.client.js';
import fs from 'fs';

const limit = pLimit(5);

// ── Types ─────────────────────────────────────────────────────

interface ActorFields {
    user: string | null;
    account: string | null;
    asset: string | null;
    ip: string | null;
}

interface GeoFields {
    city: string | null;
    country: string | null;
    org: string | null;
} 

interface NetworkFields {
    src_ip: string | null;
    dst_ip: string | null;
    dst_port: number | null;
    protocol: string | null;
    observation_count: number | null;
}

interface FileIndicator {
    filename: string;
    sha256: string | null;
    sha1: string | null;
}

export interface NormalizedEvidence {
    event_type: string;
    timestamp: string | null;
    result: string | null;          // auth result, connection_status, alert severity
    service: string | null;
    actor: ActorFields;
    geo: GeoFields | null;
    network: NetworkFields | null;  // firewall only
    file_indicators: FileIndicator[] | null; // third_party_alert only
    detection_context: Record<string, any> | null;
    raw_source: object | string | null;
}

export interface EnrichedAlert {
    alert_id: string;
    alert_type: string;
    alert_source: string;
    created_time: string;
    fetch_status: 'ok' | 'partial' | 'failed';
    evidences: NormalizedEvidence[];
}

export interface EnrichedInvestigation {
    investigation_id: string;
    details: Record<string, any>;
    pipeline_meta: {
        total_alerts: number;
        alerts_fetched: number;
        evidence_failures: string[];
    };
    alerts: EnrichedAlert[];
}

// ── Actor Extractors (per event_type) ─────────────────────────

const ACTOR_EXTRACTORS: Record<string, (data: any) => ActorFields> = {
    ingress_auth: (d) => ({
        user: d.user ?? null,
        account: d.account ?? null,
        asset: null,
        ip: d.source_ip ?? null,
    }),
    third_party_alert: (d) => ({
        user: d.user !== 'unknown' ? (d.user ?? null) : null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: null,
    }),
    firewall: (d) => ({
        user: null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: d.source_address ?? null,
    }),
    cloud_service_activity: (d) => ({
        user: d.source_user ?? null,
        account: d.source_account ?? null,
        asset: null,
        ip: d.source_json?.ClientIP ?? null,
    }),
    dns: (d) => ({
        user: null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: d.source_ip ?? d.client_ip ?? null,
    }),
    web_proxy: (d) => ({
        user: d.user ?? d.username ?? null,
        account: null,
        asset: null,
        ip: d.source_ip ?? d.client_ip ?? null,
    }),
    endpoint: (d) => ({
        user: d.user ?? d.username ?? null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: d.source_ip ?? null,
    }),
    vpn: (d) => ({
        user: d.user ?? d.username ?? null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: d.source_ip ?? d.vpn_ip ?? null,
    }),
    email: (d) => ({
        user: d.sender ?? d.from ?? null,
        account: null,
        asset: null,
        ip: d.source_ip ?? null,
    }),
    file_activity: (d) => ({
        user: d.user ?? d.username ?? null,
        account: null,
        asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
        ip: d.source_ip ?? null,
    }),
};

const defaultActorExtractor = (d: any): ActorFields => ({
    user: d.user ?? d.source_user ?? null,
    account: d.account ?? d.source_account ?? null,
    asset: d.asset !== 'unknown' ? (d.asset ?? null) : null,
    ip: d.source_address ?? d.source_ip ?? null,
});

// ── Field Extractors ──────────────────────────────────────────

function extractGeo(data: any): GeoFields | null {
    if (!data.geoip_city && !data.geoip_country_name && !data.geoip_organization) {
        return null;
    }
    return {
        city: data.geoip_city ?? null,
        country: data.geoip_country_name ?? null,
        org: data.geoip_organization ?? null,
    };
}

function extractNetwork(data: any): NetworkFields | null {
    // Only populate for firewall events — check for firewall-specific fields
    if (!data.source_address && !data.destination_address) return null;
    return {
        src_ip: data.source_address ?? null,
        dst_ip: data.destination_address ?? null,
        dst_port: data.destination_port ? Number(data.destination_port) : null,
        protocol: data.transport_protocol ?? null,
        observation_count: data.observation_count ? Number(data.observation_count) : null,
    };
}

function extractFileIndicators(data: any): FileIndicator[] | null {
    // Only for third_party_alert — MDE evidence array contains process/file info
    const mdeEvidences: any[] = data.source_json?.evidence ?? [];
    if (mdeEvidences.length === 0) return null;

    const indicators: FileIndicator[] = [];
    for (const e of mdeEvidences) {
        if (e.imageFile?.fileName) {
            indicators.push({
                filename: e.imageFile.fileName,
                sha256: e.imageFile.sha256 ?? null,
                sha1: e.imageFile.sha1 ?? null,
            });
        }
    }
    return indicators.length > 0 ? indicators : null;
}

function extractResult(eventType: string, data: any): string | null {
    switch (eventType) {
        case 'ingress_auth':
            return data.result ?? null;
        case 'firewall':
            return data.connection_status ?? null;
        case 'third_party_alert':
            return data.severity ?? null;
        case 'cloud_service_activity':
            return data.action ?? null;
        case 'dns':
            return data.response_code ?? data.query_type ?? null;
        case 'web_proxy':
            return data.action ?? data.http_status ?? null;
        case 'endpoint':
            return data.action ?? data.event_type ?? null;
        case 'vpn':
            return data.connection_status ?? data.action ?? null;
        case 'email':
            return data.action ?? data.subject ?? null;
        case 'file_activity':
            return data.action ?? data.operation ?? null;
        default:
            return data.result ?? data.action ?? null;
    }
}

function extractRawSource(data: any): object | string | null {
    // firewall has syslog string in source_data, others have source_json object
    return data.source_json ?? data.source_data ?? null;
}

// ── Core Normalizer ───────────────────────────────────────────

function normalizeEvidence(rawEvidence: any): NormalizedEvidence {
    const eventType: string = rawEvidence.event_type ?? 'unknown';
    const data: any = rawEvidence.data ?? {};

    const actorExtractor = ACTOR_EXTRACTORS[eventType] ?? defaultActorExtractor;

    return {
        event_type: eventType,
        timestamp: data.timestamp ?? rawEvidence.evented_at ?? null,
        result: extractResult(eventType, data),
        service: data.service ?? data.custom_data?.service_value ?? null,
        actor: actorExtractor(data),
        geo: extractGeo(data),
        network: extractNetwork(data),
        file_indicators: eventType === 'third_party_alert' ? extractFileIndicators(data) : null,
        detection_context: data.detection_context ?? null,
        raw_source: extractRawSource(data),
    };
}

// ── Evidence Parser (replaces your old parseEvidenceDetails) ──

function parseAndNormalizeEvidences(rawEvidences: any[]): NormalizedEvidence[] {
    return rawEvidences.map((evi: any) => {
        // Rapid7 sends data as a JSON string — parse it first
        const parsedData = typeof evi.data === 'string'
            ? (() => { try { return JSON.parse(evi.data); } catch { return {}; } })()
            : (evi.data ?? {});

        return normalizeEvidence({
            ...evi,
            data: parsedData,
        });
    });
}

// ── Single Investigation Pipeline ─────────────────────────────

const processSingleInvestigation = async (rawInv: any): Promise<EnrichedInvestigation> => {
    const parsed = parseInvestigationDetails(rawInv);
    logger.info(`Processing investigation ID: ${parsed.id}`);

    // Step 2: Fetch full investigation + alerts in parallel
    const [detailsRes, alertsRes] = await Promise.all([
        rapid7ClientVersion2.get(`/investigations/${parsed.id}`),
        rapid7ClientVersion2.get(`/investigations/${parsed.id}/alerts`),
    ]);

    const allAlerts: any[] = alertsRes.data?.data ?? [];


    logger.info(`Investigation ${parsed.id}: ${allAlerts.length} total alerts, processing top ${allAlerts.length}`);

    // Step 3: Fetch + normalize evidences for each alert in parallel (partial failure safe)
    const evidenceFailures: string[] = [];

    const enrichedAlerts: EnrichedAlert[] = await Promise.all(
        allAlerts.map(async (alert: any): Promise<EnrichedAlert> => {
            const alertRrn = alert.id;

            try {
                logger.info(`Fetching evidence for alert RRN: ${alertRrn}`);
                const evidenceRes = await rapid7ClientEvidence.get(`/alerts/${encodeURIComponent(alertRrn)}/evidences`);
                const rawEvidences: any[] = evidenceRes.data?.evidences ?? [];

                logger.info(`Alert ${alertRrn}: got ${rawEvidences.length} evidence items`);
                const normalized = parseAndNormalizeEvidences(rawEvidences);

                return {
                    alert_id: alertRrn,
                    alert_type: alert.alert_type ?? 'unknown',
                    alert_source: alert.alert_source ?? 'unknown',
                    created_time: alert.created_time,
                    fetch_status: rawEvidences.length === 0 ? 'partial' : 'ok',
                    evidences: normalized,
                };
            } catch (err: any) {
                const status = err?.response?.status ?? 'no_status';
                const body = JSON.stringify(err?.response?.data ?? {});
                logger.warn(`Failed to fetch evidence for alert ${alertRrn} — HTTP ${status}: ${err.message} | body: ${body}`);
                evidenceFailures.push(alertRrn);
                return {
                    alert_id: alertRrn,
                    alert_type: alert.alert_type ?? 'unknown',
                    alert_source: alert.alert_source ?? 'unknown',
                    created_time: alert.created_time,
                    fetch_status: 'failed',
                    evidences: [],
                };
            }
        })
    );

    const enriched: EnrichedInvestigation = {
        investigation_id: parsed.id,
        details: detailsRes.data,
        pipeline_meta: {
            total_alerts: allAlerts.length,
            alerts_fetched: allAlerts.length,
            evidence_failures: evidenceFailures,
        },
        alerts: enrichedAlerts,
    };

    // Debug write — remove before prod
    if (!fs.existsSync('investigationDetails')) {
        fs.mkdirSync('investigationDetails', { recursive: true });
    }
    fs.writeFileSync(
        `investigationDetails/context-${parsed.id}.json`,
        JSON.stringify(enriched, null, 2)
    );
    logger.info(`[CONTEXT] Saved for investigation ${parsed.id}`);

    return enriched;
};

// ── Main Entry Point ──────────────────────────────────────────

export const processInvestigation = async (investigations: any[]): Promise<EnrichedInvestigation[]> => {
    logger.info(`Processing ${investigations.length} investigations`);

    const results = await Promise.allSettled(
        investigations.map(inv => limit(() => processSingleInvestigation(inv)))
    );

    const enriched: EnrichedInvestigation[] = [];

    for (const result of results) {
        if (result.status === 'fulfilled') {
            enriched.push(result.value);
        } else {
            logger.error(`Investigation pipeline failed: ${result.reason}`);
        }
    }

    logger.info(`Pipeline complete: ${enriched.length}/${investigations.length} investigations enriched`);
    return enriched;
};