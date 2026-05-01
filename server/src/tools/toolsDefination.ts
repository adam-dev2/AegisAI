// ============================================================
// SOC Analyst — Tool Definitions
// Pass this array directly to the Anthropic messages API
// as the `tools` parameter.
//
// All 14 tools:
//   12 Rapid7 / InsightIDR tools
//    2 VirusTotal threat intel tools
// ============================================================

import type Anthropic from "@anthropic-ai/sdk";

export const rapid7ToolDefinitions: Anthropic.Tool[] = [

    // ── Log Search ───────────────────────────────────────────

    {
        name: "search_logs",
        description: `Search any InsightIDR log using a raw LEQL query.
Use for flexible ad-hoc investigations when the pre-built tools are too specific.
Call list_available_logs first if unsure of the log name.`,
        input_schema: {
            type: "object",
            properties: {
                leql_query: {
                    type: "string",
                    description: `LEQL query e.g. where(destination_user="jdoe") groupby(result)`,
                },
                log_name: {
                    type: "string",
                    description: `InsightIDR log name e.g. "Asset Authentication", "Endpoint Activity", "DNS Query", "Firewall Activity"`,
                },
                time_range: {
                    type: "string",
                    description: `"last_1h" | "last_24h" | "last_7d" | "last_30d" | ISO range "2025-04-01T00:00Z/2025-04-30T00:00Z"`,
                },
                limit: {
                    type: "number",
                    description: "Max events to return (default 50)",
                },
            },
            required: ["leql_query", "log_name", "time_range"],
        },
    },

    {
        name: "search_auth_logs",
        description: `Search authentication events in InsightIDR.
Use for: brute force, credential stuffing, impossible travel, failed logins, account takeover investigations.
Filters by username, source IP, auth result, and service (VPN/SSH/RDP/O365).`,
        input_schema: {
            type: "object",
            properties: {
                username: { type: "string", description: "Target username to filter by" },
                source_ip: { type: "string", description: "Source IP address to filter by" },
                result_filter: {
                    type: "string",
                    enum: ["FAILED", "SUCCESS", "ALL"],
                    description: "Filter by authentication result (default ALL)",
                },
                service: {
                    type: "string",
                    description: "Service to filter by e.g. VPN, SSH, RDP, O365",
                },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
                limit: { type: "number", description: "Max events to return (default 100)" },
            },
            required: ["time_range"],
        },
    },

    {
        name: "search_process_logs",
        description: `Search endpoint process execution logs in InsightIDR.
Use for: LOLBin abuse, malware execution, suspicious command lines, lateral movement via remote execution.
Filter by hostname, process name, command line content, or parent process.`,
        input_schema: {
            type: "object",
            properties: {
                hostname: { type: "string", description: "Asset hostname to filter by" },
                process_name: { type: "string", description: "Process name (partial match supported)" },
                command_line_contains: { type: "string", description: "Substring to search in command line" },
                parent_process: { type: "string", description: "Parent process name (partial match)" },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
                limit: { type: "number", description: "Max events to return (default 50)" },
            },
            required: ["time_range"],
        },
    },

    {
        name: "search_dns_logs",
        description: `Search DNS query logs in InsightIDR.
Use for: C2 beaconing detection, DGA domain identification, reverse-resolving unknown IPs to domains.
Filter by source asset, queried domain, or resolved IP.`,
        input_schema: {
            type: "object",
            properties: {
                hostname: { type: "string", description: "Source asset making the DNS queries" },
                queried_domain: { type: "string", description: "Domain being resolved (partial match)" },
                ip_address: { type: "string", description: "Resolved IP address to reverse-lookup" },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
                limit: { type: "number", description: "Max events to return (default 100)" },
            },
            required: ["time_range"],
        },
    },

    {
        name: "search_network_flows",
        description: `Search firewall/NetFlow logs in InsightIDR.
Use for: tracing C2 communication, data exfiltration, port scans, lateral movement via network.
Filter by source/destination IP, destination port, protocol, or direction.`,
        input_schema: {
            type: "object",
            properties: {
                src_ip: { type: "string", description: "Source IP address" },
                dst_ip: { type: "string", description: "Destination IP address" },
                dst_port: { type: "number", description: "Destination port number" },
                protocol: {
                    type: "string",
                    enum: ["TCP", "UDP", "ICMP"],
                    description: "Network protocol",
                },
                direction: {
                    type: "string",
                    enum: ["inbound", "outbound"],
                    description: "Traffic direction",
                },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
                limit: { type: "number", description: "Max events to return (default 100)" },
            },
            required: ["time_range"],
        },
    },

    // ── User Intelligence ─────────────────────────────────────

    {
        name: "get_user_activity",
        description: `Get a full activity timeline for a user: recent logins and related investigations.
Use this as the FIRST step whenever a user is the primary actor in an alert.
Covers auth events across all services and any open/closed investigations linked to the user.`,
        input_schema: {
            type: "object",
            properties: {
                username: { type: "string", description: "Username or display name to look up" },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
            },
            required: ["username", "time_range"],
        },
    },

    {
        name: "get_user_risk",
        description: `Get a user's full InsightIDR profile and risk posture.
Returns: account status (locked/disabled), group memberships, linked AD/O365 accounts,
admin flag, first/last seen, and breach monitoring status.
Use after get_user_activity to understand if an account has elevated risk.`,
        input_schema: {
            type: "object",
            properties: {
                username: { type: "string", description: "Username or display name to look up" },
            },
            required: ["username"],
        },
    },

    // ── Asset Intelligence ────────────────────────────────────

    {
        name: "get_asset_profile",
        description: `Get an asset's full profile: OS, IP addresses, agent status, criticality tag, and recent process activity.
Use this to assess blast radius when an asset is implicated in an alert.
time_range controls how far back process activity is pulled — use "last_7d" for multi-day investigations.`,
        input_schema: {
            type: "object",
            properties: {
                identifier: {
                    type: "string",
                    description: "Hostname or IP address of the asset",
                },
                time_range: {
                    type: "string",
                    description: `How far back to pull process activity. Default "last_24h". Use "last_7d" for multi-day investigations.`,
                },
            },
            required: ["identifier"],
        },
    },

    {
        name: "get_asset_alert_history",
        description: `Get previous investigations and alerts linked to an asset.
Use to detect repeat threats, persistent actors, or whether this asset is a known problem.
Optionally filter by severity to focus on high-priority historical incidents.`,
        input_schema: {
            type: "object",
            properties: {
                identifier: { type: "string", description: "Hostname or IP address of the asset" },
                time_range: { type: "string", description: `"last_7d" | "last_30d" | ISO range` },
                severity: {
                    type: "string",
                    enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    description: "Filter investigations by severity level",
                },
            },
            required: ["identifier", "time_range"],
        },
    },

    {
        name: "get_asset_login_history",
        description: `List all authentication events directed TO a specific asset (RDP, SSH, local login etc).
Use to find unauthorized access, credential reuse, or brute force attacks on a host.
Different from search_auth_logs which searches by actor — this searches by destination asset.`,
        input_schema: {
            type: "object",
            properties: {
                hostname: { type: "string", description: "Hostname of the target asset" },
                time_range: { type: "string", description: `"last_1h" | "last_24h" | "last_7d" | ISO range` },
                result_filter: {
                    type: "string",
                    enum: ["FAILED", "SUCCESS", "ALL"],
                    description: "Filter by authentication result",
                },
            },
            required: ["hostname", "time_range"],
        },
    },

    {
        name: "get_asset_vulnerabilities",
        description: `Fetch open CVEs for an asset from Rapid7 InsightVM.
Use to assess exploitability and whether a threat actor could leverage known vulnerabilities.
Results filtered by minimum CVSS score (default 7.0 — high severity and above).`,
        input_schema: {
            type: "object",
            properties: {
                identifier: {
                    type: "string",
                    description: "Hostname or IP address of the asset",
                },
                min_cvss: {
                    type: "number",
                    description: "Minimum CVSS score to include (default 7.0). Use 9.0 for critical only.",
                },
            },
            required: ["identifier"],
        },
    },

    {
        name: "list_available_logs",
        description: `List all log sources available in InsightIDR with their names and logset groupings.
Call this before search_logs when unsure which log_name to use.
Not needed for pre-built tools (search_auth_logs etc) — those resolve log names internally.`,
        input_schema: {
            type: "object",
            properties: {},
            required: [],
        },
    },

    // ── Threat Intel (VirusTotal) ─────────────────────────────

    {
        name: "check_ip_reputation",
        description: `Look up an IP address on VirusTotal for threat intelligence.
Returns: verdict (malicious/suspicious/clean/unknown), engine detection counts, ASN/owner,
country, passive DNS domains, and known threat names.

Call this for ANY external IP in:
- Firewall deny events (source_address / actor.ip)
- Authentication events (source_ip / actor.ip)  
- Network flow events (src_ip)
Do NOT call for internal RFC1918 addresses (10.x, 192.168.x, 172.16-31.x).`,
        input_schema: {
            type: "object",
            properties: {
                ip: {
                    type: "string",
                    description: "Public IPv4 or IPv6 address to look up",
                },
            },
            required: ["ip"],
        },
    },

    {
        name: "check_file_hash",
        description: `Look up a file hash on VirusTotal for threat intelligence.
Returns: verdict, engine detection counts, file type, digital signature info
(unsigned PE on a corporate machine = red flag), MITRE ATT&CK techniques from
sandbox analysis, and first/last submission dates.

Call this for ANY hash in endpoint or MDE alerts:
- file_indicators[].sha256 (preferred)
- file_indicators[].sha1
Returns a graceful "unknown" verdict if hash is not in VT database (novel/private file).`,
        input_schema: {
            type: "object",
            properties: {
                hash: {
                    type: "string",
                    description: "SHA256 (preferred), SHA1, or MD5 hash of the file",
                },
                filename: {
                    type: "string",
                    description: "Optional filename for context in the report e.g. 'services.exe'",
                },
            },
            required: ["hash"],
        },
    },
];