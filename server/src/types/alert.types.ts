
export interface ActorFields {
    user: string | null;
    account: string | null;
    asset: string | null;
    ip: string | null;
}

export interface GeoFields {
    city: string | null;
    country: string | null;
    org: string | null;
} 

export interface NetworkFields {
    src_ip: string | null;
    dst_ip: string | null;
    dst_port: number | null;
    protocol: string | null;
    observation_count: number | null;
}

export interface FileIndicator {
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