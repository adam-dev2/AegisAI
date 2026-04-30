// ============================================================
// Rapid7 InsightIDR - SOC Analyst Tool Implementations
// All tools follow the same pattern your existing threat-intel
// tools use — async functions that return structured results
// Claude can reason over.
// ============================================================

import axios from "axios";
import type { AxiosInstance } from 'axios'

// ── Config ────────────────────────────────────────────────────
const REGION = process.env.RAPID7_REGION || "us"; // us | eu | ca | au | ap
const API_KEY = process.env.RAPID7_API_KEY!;

const BASE_URLS = {
  idr: `https://${REGION}.api.insight.rapid7.com/idr/v1`,
  logSearch: `https://${REGION}.api.insight.rapid7.com/log_search`,
};

// Shared axios client
function r7Client(baseURL: string): AxiosInstance {
  return axios.create({
    baseURL,
    headers: {
      "X-Api-Key": API_KEY,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    timeout: 30_000,
  });
}

// ── Helpers ───────────────────────────────────────────────────

/** Convert relative strings like "last_24h" → epoch ms range */
function resolveTimeRange(
  timeRange: string
): { from: number; to: number } | { time_range: string } {
  const presets: Record<string, string> = {
    last_1h: "Last 1 Hour",
    last_24h: "Last 24 Hours",
    last_7d: "Last 7 Days",
    last_30d: "Last 30 Days",
    today: "Today",
    yesterday: "Yesterday",
    "this week": "This Week",
  };

  const preset = presets[timeRange.toLowerCase()];
  if (preset) return { time_range: preset };

  // ISO range e.g. "2025-04-01T00:00Z/2025-04-30T00:00Z"
  if (timeRange.includes("/")) {
    const [start, end] = timeRange.split("/");
    return {
      from: new Date(start!).getTime(),
      to: new Date(end!).getTime(),
    };
  }

  return { time_range: "Last 24 Hours" };
}

/**
 * Rapid7 Log Search is async — POST to start, poll until done.
 * Returns the final log entries array.
 */
async function runLeqlQuery(
  logId: string,
  leqlQuery: string,
  timeRange: string,
  limit = 50
): Promise<any[]> {
  const client = r7Client(BASE_URLS.logSearch);
  const timeParams = resolveTimeRange(timeRange);

  // 1. Start query
  const startRes = await client.post(`/query/logs/${logId}`, {
    leql: {
      statement: leqlQuery,
      during: timeParams,
    },
    per_page: limit,
  });

  // 2. Poll until complete
  let queryUrl: string = startRes.data.links?.find(
    (l: any) => l.rel === "Next"
  )?.href;

  let events: any[] = startRes.data.events || [];
  let completed = startRes.data.complete;

  while (!completed && queryUrl) {
    await new Promise((r) => setTimeout(r, 1000));
    const pollRes = await axios.get(queryUrl, {
      headers: { "X-Api-Key": API_KEY },
    });
    events = [...events, ...(pollRes.data.events || [])];
    completed = pollRes.data.complete;
    queryUrl = pollRes.data.links?.find((l: any) => l.rel === "Next")?.href;
  }

  return events;
}

// ── Tool 1: Search Logs (LEQL free-form) ─────────────────────
export interface SearchLogsInput {
  leql_query: string;     // e.g. where(destination_user="jdoe") groupby(result)
  log_name: string;       // "Asset Authentication" | "Firewall Activity" | etc.
  time_range: string;     // "last_24h" | "last_7d" | ISO range
  limit?: number;
}

export async function searchLogs(input: SearchLogsInput) {
  const client = r7Client(BASE_URLS.logSearch);

  // Resolve log name → log ID
  const logsRes = await client.get("/management/logs");
  const allLogs: any[] = logsRes.data.logs || [];

  const matchedLog = allLogs.find(
    (l: any) =>
      l.name.toLowerCase().includes(input.log_name.toLowerCase()) ||
      l.name.toLowerCase() === input.log_name.toLowerCase()
  );

  if (!matchedLog) {
    const available = allLogs.map((l: any) => l.name);
    return {
      error: `Log "${input.log_name}" not found`,
      available_logs: available,
    };
  }

  const events = await runLeqlQuery(
    matchedLog.id,
    input.leql_query,
    input.time_range,
    input.limit ?? 50
  );

  return {
    log_name: matchedLog.name,
    log_id: matchedLog.id,
    query: input.leql_query,
    time_range: input.time_range,
    total_events: events.length,
    events,
  };
}

// ── Tool 2: Auth Log Search (pre-built LEQL for auth events) ──
export interface SearchAuthLogsInput {
  username?: string;
  source_ip?: string;
  result_filter?: "FAILED" | "SUCCESS" | "ALL";  // default ALL
  service?: string;                               // VPN | SSH | RDP | O365
  time_range: string;
  limit?: number;
}

export async function searchAuthLogs(input: SearchAuthLogsInput) {
  const clauses: string[] = [];

  if (input.username)
    clauses.push(`destination_user="${input.username}"`);
  if (input.source_ip)
    clauses.push(`source_address="${input.source_ip}"`);
  if (input.service)
    clauses.push(`service ICONTAINS "${input.service}"`);
  if (input.result_filter && input.result_filter !== "ALL") {
    clauses.push(
      input.result_filter === "FAILED"
        ? `result ISTARTS-WITH "FAILED"`
        : `result="SUCCESS"`
    );
  }

  const whereClause =
    clauses.length > 0 ? `where(${clauses.join(" AND ")})` : "";
  const leql = `${whereClause} groupby(result, source_address, destination_user)`.trim();

  return searchLogs({
    leql_query: leql,
    log_name: "Asset Authentication",
    time_range: input.time_range,
    limit: input.limit ?? 100,
  });
}

// ── Tool 3: Process / Endpoint Execution Log Search ───────────
export interface SearchProcessLogsInput {
  hostname?: string;
  process_name?: string;
  command_line_contains?: string;
  parent_process?: string;
  time_range: string;
  limit?: number;
}

export async function searchProcessLogs(input: SearchProcessLogsInput) {
  const clauses: string[] = [];

  if (input.hostname)
    clauses.push(`asset="${input.hostname}"`);
  if (input.process_name)
    clauses.push(`process_name ICONTAINS "${input.process_name}"`);
  if (input.command_line_contains)
    clauses.push(`command_line ICONTAINS "${input.command_line_contains}"`);
  if (input.parent_process)
    clauses.push(`parent_process_name ICONTAINS "${input.parent_process}"`);

  const whereClause =
    clauses.length > 0 ? `where(${clauses.join(" AND ")})` : "";
  const leql =
    `${whereClause} groupby(asset, process_name, command_line)`.trim();

  return searchLogs({
    leql_query: leql,
    log_name: "Endpoint Activity",
    time_range: input.time_range,
    limit: input.limit ?? 50,
  });
}

// ── Tool 4: DNS Query Log Search ──────────────────────────────
export interface SearchDnsLogsInput {
  hostname?: string;        // source asset doing the query
  queried_domain?: string;  // domain being resolved
  ip_address?: string;      // resolved IP
  time_range: string;
  limit?: number;
}

export async function searchDnsLogs(input: SearchDnsLogsInput) {
  const clauses: string[] = [];

  if (input.hostname)
    clauses.push(`asset="${input.hostname}"`);
  if (input.queried_domain)
    clauses.push(`query ICONTAINS "${input.queried_domain}"`);
  if (input.ip_address)
    clauses.push(`answers ICONTAINS "${input.ip_address}"`);

  const whereClause =
    clauses.length > 0 ? `where(${clauses.join(" AND ")})` : "";
  const leql = `${whereClause} groupby(asset, query)`.trim();

  return searchLogs({
    leql_query: leql,
    log_name: "DNS Query",
    time_range: input.time_range,
    limit: input.limit ?? 100,
  });
}

// ── Tool 5: Network Flow / Firewall Log Search ────────────────
export interface SearchNetworkFlowsInput {
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol?: "TCP" | "UDP" | "ICMP";
  direction?: "inbound" | "outbound";
  time_range: string;
  limit?: number;
}

export async function searchNetworkFlows(input: SearchNetworkFlowsInput) {
  const clauses: string[] = [];

  if (input.src_ip)
    clauses.push(`source_address="${input.src_ip}"`);
  if (input.dst_ip)
    clauses.push(`destination_address="${input.dst_ip}"`);
  if (input.dst_port)
    clauses.push(`destination_port=${input.dst_port}`);
  if (input.protocol)
    clauses.push(`protocol="${input.protocol}"`);
  if (input.direction === "inbound")
    clauses.push(`direction="inbound"`);
  else if (input.direction === "outbound")
    clauses.push(`direction="outbound"`);

  const whereClause =
    clauses.length > 0 ? `where(${clauses.join(" AND ")})` : "";
  const leql =
    `${whereClause} groupby(source_address, destination_address, destination_port)`.trim();

  return searchLogs({
    leql_query: leql,
    log_name: "Firewall Activity",
    time_range: input.time_range,
    limit: input.limit ?? 100,
  });
}

// ── Tool 6: User Activity Timeline ───────────────────────────
export interface GetUserActivityInput {
  username: string;
  time_range: string;
}

export async function getUserActivity(input: GetUserActivityInput) {
  const client = r7Client(BASE_URLS.idr);

  // Step 1: Resolve user RRN from username
  const usersRes = await client.get("/users", {
    params: { search: input.username, size: 5 },
  });

  const users: any[] = usersRes.data.data || [];
  const user = users.find(
    (u: any) =>
      u.name?.toLowerCase() === input.username.toLowerCase() ||
      u.domain_name?.toLowerCase().includes(input.username.toLowerCase())
  ) || users[0];

  if (!user) {
    return { error: `User "${input.username}" not found in InsightIDR` };
  }

  // Step 2: Fetch auth events for this user
  const [authEvents, processEvents] = await Promise.all([
    searchAuthLogs({
      username: input.username,
      time_range: input.time_range,
      limit: 200,
    }),
    searchProcessLogs({
      hostname: undefined!,
      time_range: input.time_range,
      limit: 100,
    }),
  ]);

  // Step 3: Fetch any investigations involving this user
  const invRes = await client.get("/investigations", {
    params: {
      size: 20,
      sort: "created_time,desc",
      "filter[search]": input.username,
    },
  });

  return {
    user_profile: {
      rrn: user.rrn,
      name: user.name,
      domain: user.domain_name,
      email: user.email_addresses?.[0],
    },
    auth_activity: authEvents,
    process_activity: processEvents,
    related_investigations: invRes.data.data || [],
    time_range: input.time_range,
  };
}

// ── Tool 7: User Risk / Account Info ──────────────────────────
export interface GetUserRiskInput {
  username: string;
}

export async function getUserRisk(input: GetUserRiskInput) {
  const client = r7Client(BASE_URLS.idr);

  // Search for the user
  const res = await client.get("/users", {
    params: { search: input.username, size: 5 },
  });

  const users: any[] = res.data.data || [];
  const user = users.find(
    (u: any) =>
      u.name?.toLowerCase().includes(input.username.toLowerCase()) ||
      u.domain_name?.toLowerCase().includes(input.username.toLowerCase())
  ) || users[0];

  if (!user) {
    return { error: `User "${input.username}" not found` };
  }

  return {
    rrn: user.rrn,
    name: user.name,
    domain_name: user.domain_name,
    email: user.email_addresses,
    locked: user.locked_out,
    disabled: user.disabled,
    admin: user.admin,
    groups: user.groups || [],
    accounts: user.accounts || [],           // AD/O365 accounts linked
    first_seen: user.first_seen,
    last_seen: user.last_seen,
    breach_monitor_status: user.breach_info?.status,
  };
}

// ── Tool 8: Asset Profile ─────────────────────────────────────
export interface GetAssetProfileInput {
  identifier: string;   // hostname or IP
}

export async function getAssetProfile(input: GetAssetProfileInput) {
  const client = r7Client(BASE_URLS.idr);

  const res = await client.get("/assets", {
    params: { search: input.identifier, size: 5 },
  });

  const assets: any[] = res.data.data || [];
  const asset = assets.find(
    (a: any) =>
      a.hostname?.toLowerCase() === input.identifier.toLowerCase() ||
      a.ip_addresses?.some((ip: any) => ip.ip === input.identifier)
  ) || assets[0];

  if (!asset) {
    return { error: `Asset "${input.identifier}" not found` };
  }

  // Enrich with processes running on this asset
  const processRes = await searchProcessLogs({
    hostname: asset.hostname,
    time_range: "last_24h",
    limit: 20,
  });

  return {
    rrn: asset.rrn,
    hostname: asset.hostname,
    ip_addresses: asset.ip_addresses,
    mac_addresses: asset.mac_addresses,
    os: asset.os_description,
    last_seen: asset.last_seen_time,
    agent_installed: asset.agent_installed,
    restricted: asset.restricted,
    criticality_tag: asset.criticality_tag,
    insight_agent_status: asset.insight_agent_status,
    recent_processes: processRes,
  };
}

// ── Tool 9: Asset Alert History ───────────────────────────────
export interface GetAssetAlertHistoryInput {
  identifier: string;   // hostname or IP
  time_range: string;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

export async function getAssetAlertHistory(input: GetAssetAlertHistoryInput) {
  const client = r7Client(BASE_URLS.idr);

  // Get investigations linked to this asset
  const invRes = await client.get("/investigations", {
    params: {
      size: 50,
      sort: "created_time,desc",
      "filter[search]": input.identifier,
    },
  });

  let investigations: any[] = invRes.data.data || [];

  // Filter by severity if requested
  if (input.severity) {
    investigations = investigations.filter(
      (inv: any) => inv.priority?.toUpperCase() === input.severity
    );
  }

  // Fetch alerts for the top 5 most recent investigations in parallel
  const top5 = investigations.slice(0, 5);
  const alertsByInv = await Promise.all(
    top5.map(async (inv: any) => {
      const alertRes = await client.get(
        `/investigations/${inv.id}/alerts`
      ).catch(() => ({ data: { data: [] } }));
      return {
        investigation_id: inv.id,
        investigation_title: inv.title,
        priority: inv.priority,
        status: inv.status,
        created_time: inv.created_time,
        alerts: alertRes.data.data || [],
      };
    })
  );

  return {
    asset: input.identifier,
    time_range: input.time_range,
    total_investigations: investigations.length,
    investigations_with_alerts: alertsByInv,
  };
}

// ── Tool 10: Asset Login History ──────────────────────────────
export interface GetAssetLoginHistoryInput {
  hostname: string;
  time_range: string;
  result_filter?: "FAILED" | "SUCCESS" | "ALL";
}

export async function getAssetLoginHistory(input: GetAssetLoginHistoryInput) {
  const leql = input.result_filter && input.result_filter !== "ALL"
    ? `where(destination_asset="${input.hostname}" AND result ISTARTS-WITH "${input.result_filter}") groupby(destination_user, result, source_asset_address)`
    : `where(destination_asset="${input.hostname}") groupby(destination_user, result, source_asset_address)`;

  return searchLogs({
    leql_query: leql,
    log_name: "Asset Authentication",
    time_range: input.time_range,
    limit: 200,
  });
}

// ── Tool 11: Vulnerability Posture for Asset ──────────────────
export interface GetAssetVulnsInput {
  identifier: string;
  min_cvss?: number;    // default 7.0
}

export async function getAssetVulnerabilities(input: GetAssetVulnsInput) {
  // Rapid7 Insight VM / InsightIDR uses the /idr/v1/assets API
  // Vuln data is in the InsightVM API — same API key works
  const client = axios.create({
    baseURL: `https://${REGION}.api.insight.rapid7.com/vm/v4`,
    headers: { "X-Api-Key": API_KEY, "Content-Type": "application/json" },
    timeout: 30_000,
  });

  // Find the asset
  const searchRes = await client.post("/integration/assets/search", {
    filters: [
      {
        field: input.identifier.includes(".")
          ? "ip-address"
          : "host-name",
        operator: "is",
        value: input.identifier,
      },
    ],
    current_time: new Date().toISOString(),
  });

  const asset = searchRes.data.data?.[0];
  if (!asset) {
    return { error: `Asset not found in InsightVM: ${input.identifier}` };
  }

  // Get vulnerabilities for asset
  const vulnRes = await client.get(
    `/integration/assets/${asset.id}/vulnerabilities`,
    { params: { size: 100 } }
  );

  const vulns: any[] = vulnRes.data.data || [];
  const minCvss = input.min_cvss ?? 7.0;
  const filtered = vulns.filter(
    (v: any) => (v.cvss_v3_score || v.cvss_v2_score || 0) >= minCvss
  );

  return {
    asset_id: asset.id,
    hostname: asset.host_name,
    ip: asset.ip,
    os: asset.os_system,
    total_vulns: vulns.length,
    filtered_above_cvss: minCvss,
    vulnerabilities: filtered.map((v: any) => ({
      id: v.id,
      title: v.title,
      cvss_v3: v.cvss_v3_score,
      cvss_v2: v.cvss_v2_score,
      severity: v.severity,
      exploitable: v.exploits > 0,
      exploits_count: v.exploits,
      published: v.published,
      solution: v.solution?.summary,
    })),
  };
}

// ── Tool 12: List All Logs (for Claude to pick the right one) ─
// Claude can call this first if it doesn't know which log to use
export async function listAvailableLogs() {
  const client = r7Client(BASE_URLS.logSearch);
  const res = await client.get("/management/logs");
  const logs: any[] = res.data.logs || [];
  return logs.map((l: any) => ({
    id: l.id,
    name: l.name,
    logset_name: l.logsets_info?.[0]?.name,
  }));
}

// ── Tool Registry (Claude tool definitions) ───────────────────
// Drop these into your existing toolDefinitions array

export const rapid7ToolDefinitions = [
  {
    name: "search_logs",
    description:
      "Search any InsightIDR log using a raw LEQL query. Use this for flexible, ad-hoc investigations when other tools are too specific. Call list_available_logs first if unsure of the log name.",
    input_schema: {
      type: "object",
      properties: {
        leql_query: {
          type: "string",
          description:
            'LEQL query e.g. where(destination_user="jdoe") groupby(result)',
        },
        log_name: {
          type: "string",
          description:
            'InsightIDR log name e.g. "Asset Authentication", "Endpoint Activity", "DNS Query", "Firewall Activity"',
        },
        time_range: {
          type: "string",
          description:
            '"last_1h" | "last_24h" | "last_7d" | "last_30d" | "today" | ISO range "2025-04-01T00:00Z/2025-04-30T00:00Z"',
        },
        limit: { type: "number", description: "Max events to return (default 50)" },
      },
      required: ["leql_query", "log_name", "time_range"],
    },
  },
  {
    name: "search_auth_logs",
    description:
      "Search authentication events. Use for brute force, credential stuffing, impossible travel, failed logins, or account takeover investigations.",
    input_schema: {
      type: "object",
      properties: {
        username: { type: "string" },
        source_ip: { type: "string" },
        result_filter: {
          type: "string",
          enum: ["FAILED", "SUCCESS", "ALL"],
          description: "Filter by auth result",
        },
        service: {
          type: "string",
          description: "e.g. VPN, SSH, RDP, O365",
        },
        time_range: { type: "string" },
        limit: { type: "number" },
      },
      required: ["time_range"],
    },
  },
  {
    name: "search_process_logs",
    description:
      "Search endpoint process execution logs. Use for LOLBin abuse, malware execution, suspicious command lines, or lateral movement via remote execution.",
    input_schema: {
      type: "object",
      properties: {
        hostname: { type: "string" },
        process_name: { type: "string" },
        command_line_contains: { type: "string" },
        parent_process: { type: "string" },
        time_range: { type: "string" },
        limit: { type: "number" },
      },
      required: ["time_range"],
    },
  },
  {
    name: "search_dns_logs",
    description:
      "Search DNS query logs. Use for C2 beaconing, DGA domain detection, or resolving unknown IPs back to domains.",
    input_schema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Source asset making DNS queries" },
        queried_domain: { type: "string" },
        ip_address: { type: "string", description: "Resolved IP to reverse-lookup" },
        time_range: { type: "string" },
        limit: { type: "number" },
      },
      required: ["time_range"],
    },
  },
  {
    name: "search_network_flows",
    description:
      "Search firewall/NetFlow logs. Use to trace C2 communication, data exfiltration, port scans, or lateral movement via network.",
    input_schema: {
      type: "object",
      properties: {
        src_ip: { type: "string" },
        dst_ip: { type: "string" },
        dst_port: { type: "number" },
        protocol: { type: "string", enum: ["TCP", "UDP", "ICMP"] },
        direction: { type: "string", enum: ["inbound", "outbound"] },
        time_range: { type: "string" },
        limit: { type: "number" },
      },
      required: ["time_range"],
    },
  },
  {
    name: "get_user_activity",
    description:
      "Get a full activity timeline for a user: logins, endpoint activity, and related investigations. Use this as the FIRST step whenever a user is the primary actor in an alert.",
    input_schema: {
      type: "object",
      properties: {
        username: { type: "string" },
        time_range: { type: "string" },
      },
      required: ["username", "time_range"],
    },
  },
  {
    name: "get_user_risk",
    description:
      "Get a user's InsightIDR profile: account status, group memberships, linked AD/O365 accounts, admin flag, lock status, and breach info.",
    input_schema: {
      type: "object",
      properties: {
        username: { type: "string" },
      },
      required: ["username"],
    },
  },
  {
    name: "get_asset_profile",
    description:
      "Get an asset's full profile: OS, IPs, agent status, criticality, and recent process activity. Use this to assess blast radius when an asset is implicated.",
    input_schema: {
      type: "object",
      properties: {
        identifier: {
          type: "string",
          description: "Hostname or IP address",
        },
      },
      required: ["identifier"],
    },
  },
  {
    name: "get_asset_alert_history",
    description:
      "Get previous investigations and alerts linked to an asset. Use to detect repeat threats, persistent actors, or whether this asset is a known problem.",
    input_schema: {
      type: "object",
      properties: {
        identifier: { type: "string" },
        time_range: { type: "string" },
        severity: {
          type: "string",
          enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        },
      },
      required: ["identifier", "time_range"],
    },
  },
  {
    name: "get_asset_login_history",
    description:
      "List all authentication events TO a specific asset. Use to find unauthorized access, credential reuse, or RDP/SSH brute force on a host.",
    input_schema: {
      type: "object",
      properties: {
        hostname: { type: "string" },
        time_range: { type: "string" },
        result_filter: {
          type: "string",
          enum: ["FAILED", "SUCCESS", "ALL"],
        },
      },
      required: ["hostname", "time_range"],
    },
  },
  {
    name: "get_asset_vulnerabilities",
    description:
      "Fetch open CVEs for an asset from InsightVM. Use to assess exploitability and whether a threat actor could leverage known vulnerabilities on the asset.",
    input_schema: {
      type: "object",
      properties: {
        identifier: { type: "string", description: "Hostname or IP" },
        min_cvss: {
          type: "number",
          description: "Minimum CVSS score (default 7.0)",
        },
      },
      required: ["identifier"],
    },
  },
  {
    name: "list_available_logs",
    description:
      "List all log sources available in InsightIDR with their IDs and logset groupings. Call this when unsure which log_name to pass to search_logs.",
    input_schema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// ── Tool Executor (wire into your existing dispatch switch) ───
export async function executeRapid7Tool(
  toolName: string,
  toolInput: any
): Promise<any> {
  switch (toolName) {
    case "search_logs":
      return searchLogs(toolInput);
    case "search_auth_logs":
      return searchAuthLogs(toolInput);
    case "search_process_logs":
      return searchProcessLogs(toolInput);
    case "search_dns_logs":
      return searchDnsLogs(toolInput);
    case "search_network_flows":
      return searchNetworkFlows(toolInput);
    case "get_user_activity":
      return getUserActivity(toolInput);
    case "get_user_risk":
      return getUserRisk(toolInput);
    case "get_asset_profile":
      return getAssetProfile(toolInput);
    case "get_asset_alert_history":
      return getAssetAlertHistory(toolInput);
    case "get_asset_login_history":
      return getAssetLoginHistory(toolInput);
    case "get_asset_vulnerabilities":
      return getAssetVulnerabilities(toolInput);
    case "list_available_logs":
      return listAvailableLogs();
    default:
      throw new Error(`Unknown Rapid7 tool: ${toolName}`);
  }
}