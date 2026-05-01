// ============================================================
// MOCK ANALYSIS — Full End-to-End Scenario
// 
// Scenario: "Operation Phantom Admin"
// A compromised admin account (john.carter) is being used to:
//   1. Brute-force O365 from a malicious external IP
//   2. Execute a known RAT on their corporate laptop
//   3. Make suspicious DNS queries to a C2 domain
//   4. Exfiltrate data via firewall-allowed outbound connection
//
// Tool call order (14 total, limit hits at 10):
//   1.  check_ip_reputation       — external auth IP is malicious
//   2.  get_user_activity         — john.carter timeline
//   3.  get_user_risk             — admin account, breach confirmed
//   4.  search_auth_logs          — confirm pattern of failures
//   5.  get_asset_profile         — laptop profile
//   6.  check_file_hash (sha256)  — RAT binary confirmed malicious
//   7.  check_file_hash (sha1)    — second file suspicious
//   8.  search_dns_logs           — C2 domain queries confirmed
//   9.  search_network_flows      — outbound C2 traffic confirmed
//   10. get_asset_vulnerabilities — LIMIT HIT after this call
//   -- Stop, send results + force report --
//   [NOT called: get_asset_alert_history, get_asset_login_history,
//                list_available_logs, search_logs, search_process_logs]
// ============================================================

// ── 1. Mock EnrichedInvestigation (input to analyzeInvestigation) ──

export const mockEnrichedInvestigation = {
    investigation_id: "inv-phantom-admin-001",
    details: {
        rrn: "rrn:investigation:us3:fa2fadc9:investigation:PHANTOM001",
        title: "SA - Multiple login failures from same user - O365",
        source: "ALERT",
        status: "OPEN",
        priority: "HIGH",
        created_time: "2026-04-30T09:15:00.000Z",
        last_accessed: "2026-04-30T09:15:01.000Z",
        disposition: null,
        assignee: { name: "SOC Tier 1", email: "soc-tier1@company.com" },
        responsibility: null,
    },
    pipeline_meta: {
        total_alerts: 3,
        alerts_fetched: 3,
        evidence_failures: [],
    },
    alerts: [
        // ── Alert 1: O365 auth failures ──────────────────────
        {
            alert_id: "rrn:alerts:us3:fa2fadc9:alert:1:auth001",
            alert_type: "SA - Multiple login failures from same user - O365",
            alert_source: "Attacker Behavior Analytics",
            created_time: "2026-04-30T09:14:00.000Z",
            fetch_status: "ok",
            evidences: [
                {
                    event_type: "ingress_auth",
                    timestamp: "2026-04-30T09:10:23.000Z",
                    result: "FAILED_BAD_PASSWORD",
                    service: "o365",
                    actor: {
                        user: "John Carter",
                        account: "john.carter@company.com",
                        asset: null,
                        ip: "185.220.101.47",       // Tor exit node — malicious
                    },
                    geo: {
                        city: "Frankfurt",
                        country: "Germany",
                        org: "Tor Project",
                    },
                    network: null,
                    file_indicators: null,
                    detection_context: {
                        user: { user_age_mins: 525600 },   // 1 year old account
                        account: { account_age_mins: 525600 },
                    },
                    raw_source: {
                        Operation: "UserLoginFailed",
                        LogonError: "InvalidUserNameOrPassword",
                        ActorIpAddress: "185.220.101.47",
                        UserId: "john.carter@company.com",
                        ErrorNumber: "50126",
                    },
                },
                {
                    event_type: "ingress_auth",
                    timestamp: "2026-04-30T09:12:45.000Z",
                    result: "SUCCESS",              // eventually succeeded — account taken over
                    service: "o365",
                    actor: {
                        user: "John Carter",
                        account: "john.carter@company.com",
                        asset: null,
                        ip: "185.220.101.47",
                    },
                    geo: {
                        city: "Frankfurt",
                        country: "Germany",
                        org: "Tor Project",
                    },
                    network: null,
                    file_indicators: null,
                    detection_context: null,
                    raw_source: {
                        Operation: "UserLoggedIn",
                        ActorIpAddress: "185.220.101.47",
                        UserId: "john.carter@company.com",
                    },
                },
            ],
        },

        // ── Alert 2: MDE endpoint alert (RAT) ────────────────
        {
            alert_id: "rrn:alerts:us3:fa2fadc9:alert:1:mde002",
            alert_type: "Microsoft Defender for Endpoint - Custom Alert",
            alert_source: "Attacker Behavior Analytics",
            created_time: "2026-04-30T09:05:00.000Z",
            fetch_status: "ok",
            evidences: [
                {
                    event_type: "third_party_alert",
                    timestamp: "2026-04-30T09:02:11.000Z",
                    result: "high",
                    service: null,
                    actor: {
                        user: "john.carter",
                        account: null,
                        asset: "JCARTER-LAPTOP",
                        ip: null,
                    },
                    geo: null,
                    network: null,
                    file_indicators: [
                        {
                            filename: "svchost32.exe",
                            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  // known AsyncRAT hash
                            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        },
                        {
                            filename: "update_helper.dll",
                            sha256: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
                            sha1: "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c",
                        },
                    ],
                    detection_context: null,
                    raw_source: {
                        title: "Suspicious process executed from temp directory",
                        category: "Malware",
                        severity: "High",
                        recommendedActions: "Isolate device immediately",
                        evidence: [
                            {
                                "@odata.type": "#microsoft.graph.security.processEvidence",
                                processCommandLine: "C:\\Users\\jcarter\\AppData\\Local\\Temp\\svchost32.exe -s",
                                imageFile: {
                                    fileName: "svchost32.exe",
                                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                },
                                verdict: "malicious",
                            },
                        ],
                    },
                },
            ],
        },

        // ── Alert 3: Firewall excessive denies ────────────────
        {
            alert_id: "rrn:alerts:us3:fa2fadc9:alert:1:fw003",
            alert_type: "SA - Excessive Firewall denies from Remote Source IP",
            alert_source: "Attacker Behavior Analytics",
            created_time: "2026-04-30T08:58:00.000Z",
            fetch_status: "ok",
            evidences: [
                {
                    event_type: "firewall",
                    timestamp: "2026-04-30T08:55:12.000Z",
                    result: "DENY",
                    service: "tcp/4444",            // Metasploit default port
                    actor: {
                        user: null,
                        account: null,
                        asset: null,
                        ip: "185.220.101.47",       // same Tor IP
                    },
                    geo: null,
                    network: {
                        src_ip: "185.220.101.47",
                        dst_ip: "203.0.113.55",     // company external IP
                        dst_port: 4444,
                        protocol: "tcp",
                        observation_count: 47,
                    },
                    detection_context: null,
                    raw_source: `<189>date=2026-04-30 time=08:55:12 devname="FW-EDGE-01" srcip=185.220.101.47 srcport=54821 dstip=203.0.113.55 dstport=4444 action="deny" service="tcp/4444"`,
                },
                {
                    event_type: "firewall",
                    timestamp: "2026-04-30T09:01:00.000Z",
                    result: "ALLOW",                // outbound C2 callback — allowed!
                    service: "HTTPS",
                    actor: {
                        user: null,
                        account: null,
                        asset: "JCARTER-LAPTOP",
                        ip: "10.0.1.45",
                    },
                    geo: null,
                    network: {
                        src_ip: "10.0.1.45",        // laptop internal IP
                        dst_ip: "185.220.101.47",   // same Tor IP — outbound C2
                        dst_port: 443,
                        protocol: "tcp",
                        observation_count: 12,
                    },
                    detection_context: null,
                    raw_source: `<189>date=2026-04-30 time=09:01:00 devname="FW-EDGE-01" srcip=10.0.1.45 srcport=49821 dstip=185.220.101.47 dstport=443 action="allow" service="HTTPS"`,
                },
            ],
        },
    ],
};

// ── 2. Mock Tool Results (what each tool returns) ─────────────

export const mockToolResults = {

    // Tool 1 — check_ip_reputation("185.220.101.47")
    check_ip_reputation: {
        ip: "185.220.101.47",
        verdict: "malicious",
        malicious_engines: 42,
        suspicious_engines: 3,
        clean_engines: 11,
        total_engines: 56,
        asn: 205100,
        as_owner: "F3 Netze e.V.",
        country: "DE",
        network: "185.220.100.0/22",
        tags: ["tor-exit-node", "anonymizer", "threat-actor-infrastructure"],
        threat_names: [
            "TorExitNode", "Brute-Force", "Scanning", "C2", "AsyncRAT-C2"
        ],
        passive_dns_domains: [
            "c2.phantom-net.xyz",
            "update.totally-legit-cdn.com",
            "185-220-101-47.torservers.net",
        ],
        times_submitted: 8821,
        last_analysis_date: "2026-04-30T06:00:00.000Z",
    },

    // Tool 2 — get_user_activity("john.carter", "last_24h")
    get_user_activity: {
        user_profile: {
            rrn: "rrn:uba:us3:fa2fadc9:user:JCARTER001",
            name: "John Carter",
            domain: "company.com",
            email: "john.carter@company.com",
        },
        auth_activity: {
            total_events: 28,
            events: [
                { timestamp: "2026-04-30T07:30:00Z", result: "SUCCESS", source_address: "10.0.1.45",      service: "o365" },
                { timestamp: "2026-04-30T09:10:23Z", result: "FAILED_BAD_PASSWORD", source_address: "185.220.101.47", service: "o365" },
                { timestamp: "2026-04-30T09:10:51Z", result: "FAILED_BAD_PASSWORD", source_address: "185.220.101.47", service: "o365" },
                { timestamp: "2026-04-30T09:11:14Z", result: "FAILED_BAD_PASSWORD", source_address: "185.220.101.47", service: "o365" },
                { timestamp: "2026-04-30T09:12:45Z", result: "SUCCESS",             source_address: "185.220.101.47", service: "o365" },
                // ... 23 more
            ],
        },
        related_investigations: [
            {
                id: "inv-old-001",
                title: "SA - Anomalous O365 login location",
                priority: "LOW",
                status: "CLOSED",
                disposition: "BENIGN",
                created_time: "2026-03-15T10:00:00Z",
            },
        ],
        time_range: "last_24h",
    },

    // Tool 3 — get_user_risk("john.carter")
    get_user_risk: {
        rrn: "rrn:uba:us3:fa2fadc9:user:JCARTER001",
        name: "John Carter",
        domain_name: "company.com",
        email: ["john.carter@company.com"],
        locked: false,
        disabled: false,
        admin: true,                            // ← ADMIN ACCOUNT — critical
        groups: ["Domain Admins", "IT-Infrastructure", "VPN-Users"],
        accounts: ["john.carter@company.com", "COMPANY\\jcarter"],
        first_seen: "2023-01-15T00:00:00Z",
        last_seen: "2026-04-30T09:12:45Z",
        breach_monitor_status: "BREACHED",      // ← confirmed breach
    },

    // Tool 4 — search_auth_logs({ username: "john.carter", result_filter: "FAILED", time_range: "last_24h" })
    search_auth_logs: {
        log_name: "Asset Authentication",
        query: `where(destination_user="john.carter" AND result ISTARTS-WITH "FAILED") groupby(result, source_address, destination_user)`,
        time_range: "last_24h",
        total_events: 17,
        events: [
            { source_address: "185.220.101.47", result: "FAILED_BAD_PASSWORD", count: 14, destination_user: "john.carter" },
            { source_address: "185.220.101.47", result: "FAILED_MFA",          count: 2,  destination_user: "john.carter" },
            { source_address: "185.220.101.47", result: "FAILED_BAD_PASSWORD", count: 1,  destination_user: "john.carter" },
        ],
    },

    // Tool 5 — get_asset_profile("JCARTER-LAPTOP")
    get_asset_profile: {
        rrn: "rrn:uba:us3:fa2fadc9:asset:LAPTOP001",
        hostname: "JCARTER-LAPTOP",
        ip_addresses: [{ ip: "10.0.1.45", type: "private" }],
        mac_addresses: ["00:1A:2B:3C:4D:5E"],
        os: "Windows 11 Pro 23H2",
        last_seen: "2026-04-30T09:14:00Z",
        agent_installed: true,
        restricted: false,
        criticality_tag: "High",               // ← high criticality asset
        insight_agent_status: "active",
        time_range_used: "last_24h",
        recent_processes: {
            total_events: 8,
            events: [
                { asset: "JCARTER-LAPTOP", process_name: "svchost32.exe", command_line: "C:\\Users\\jcarter\\AppData\\Local\\Temp\\svchost32.exe -s" },
                { asset: "JCARTER-LAPTOP", process_name: "powershell.exe", command_line: "powershell -enc JABjAGwAaQBlAG4AdA..." },  // encoded PS
                { asset: "JCARTER-LAPTOP", process_name: "cmd.exe",        command_line: "cmd /c whoami && net user" },
            ],
        },
    },

    // Tool 6 — check_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "svchost32.exe")
    check_file_hash_svchost32: {
        hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        filename: "svchost32.exe",
        verdict: "malicious",
        malicious_engines: 58,
        suspicious_engines: 2,
        clean_engines: 4,
        total_engines: 64,
        file_type: "Win32 EXE",
        file_size: 487424,
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        md5: "d41d8cd98f00b204e9800998ecf8427e",
        popular_threat_name: "AsyncRAT",
        tags: ["rat", "async-rat", "c2", "persistence"],
        mitre_attack_techniques: ["T1059.001", "T1547.001", "T1071.001", "T1095", "T1027"],
        signature_verified: false,              // ← UNSIGNED — red flag
        signer: null,
        first_seen: "2026-03-01T00:00:00Z",
        last_seen: "2026-04-30T08:00:00Z",
        times_submitted: 1243,
    },

    // Tool 7 — check_file_hash("aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f", "update_helper.dll")
    check_file_hash_dll: {
        hash: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
        filename: "update_helper.dll",
        verdict: "suspicious",
        malicious_engines: 2,
        suspicious_engines: 8,
        clean_engines: 54,
        total_engines: 64,
        file_type: "Win32 DLL",
        file_size: 102400,
        sha256: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
        sha1: "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c",
        md5: "cfcd208495d565ef66e7dff9f98764da",
        popular_threat_name: "AsyncRAT.Loader",
        tags: ["loader", "dll-sideloading"],
        mitre_attack_techniques: ["T1574.002", "T1055"],
        signature_verified: false,
        signer: null,
        first_seen: "2026-03-15T00:00:00Z",
        last_seen: "2026-04-30T08:05:00Z",
        times_submitted: 312,
    },

    // Tool 8 — search_dns_logs({ hostname: "JCARTER-LAPTOP", time_range: "last_24h" })
    search_dns_logs: {
        log_name: "DNS Query",
        query: `where(asset="JCARTER-LAPTOP") groupby(asset, query)`,
        time_range: "last_24h",
        total_events: 5,
        events: [
            { asset: "JCARTER-LAPTOP", query: "c2.phantom-net.xyz",            count: 87 },  // ← 87 queries = beaconing
            { asset: "JCARTER-LAPTOP", query: "update.totally-legit-cdn.com",  count: 24 },  // ← passive DNS match
            { asset: "JCARTER-LAPTOP", query: "google.com",                    count: 12 },
            { asset: "JCARTER-LAPTOP", query: "microsoft.com",                 count: 8  },
            { asset: "JCARTER-LAPTOP", query: "windowsupdate.com",             count: 3  },
        ],
    },

    // Tool 9 — search_network_flows({ src_ip: "10.0.1.45", dst_ip: "185.220.101.47", time_range: "last_24h" })
    search_network_flows: {
        log_name: "Firewall Activity",
        query: `where(source_address="10.0.1.45" AND destination_address="185.220.101.47") groupby(source_address, destination_address, destination_port)`,
        time_range: "last_24h",
        total_events: 3,
        events: [
            { source_address: "10.0.1.45", destination_address: "185.220.101.47", destination_port: 443,  count: 12, status: "ALLOW" },
            { source_address: "10.0.1.45", destination_address: "185.220.101.47", destination_port: 8443, count: 4,  status: "ALLOW" },
            { source_address: "10.0.1.45", destination_address: "185.220.101.47", destination_port: 4444, count: 2,  status: "DENY"  },
        ],
    },

    // Tool 10 — get_asset_vulnerabilities("JCARTER-LAPTOP")  ← TOOL LIMIT HIT AFTER THIS
    get_asset_vulnerabilities: {
        asset_id: "asset-laptop-001",
        hostname: "JCARTER-LAPTOP",
        ip: "10.0.1.45",
        os: "Windows 11 Pro",
        total_vulns: 23,
        filtered_above_cvss: 7.0,
        vulnerabilities: [
            {
                id: "vuln-001",
                title: "CVE-2024-21412: Microsoft Defender SmartScreen Bypass",
                cvss_v3: 8.1,
                cvss_v2: null,
                severity: "High",
                exploitable: true,
                exploits_count: 3,
                published: "2024-02-13T00:00:00Z",
                solution: "Apply Microsoft security update KB5034765",
            },
            {
                id: "vuln-002",
                title: "CVE-2024-30051: Windows DWM Core Library Privilege Escalation",
                cvss_v3: 7.8,
                cvss_v2: null,
                severity: "High",
                exploitable: true,
                exploits_count: 1,
                published: "2024-05-14T00:00:00Z",
                solution: "Apply Microsoft security update KB5037771",
            },
        ],
    },

    // Tools NOT called due to limit:
    // get_asset_alert_history, get_asset_login_history,
    // list_available_logs, search_logs, search_process_logs
};

// ── 3. Expected Final Report (what Claude should produce) ─────

export const expectedInvestigationReport = {
    investigation_id: "inv-phantom-admin-001",
    title: "SA - Multiple login failures from same user - O365",
    priority: "HIGH",

    verdict: "TRUE_POSITIVE",
    severity: "CRITICAL",
    confidence: "HIGH",

    summary: `Domain Admin account john.carter@company.com has been fully compromised. 
An attacker using the Tor exit node 185.220.101.47 (42/56 VT engines: malicious, tagged AsyncRAT-C2) 
successfully authenticated to O365 after 14 failed attempts, deployed a confirmed AsyncRAT RAT 
(58/64 VT engines) on JCARTER-LAPTOP, established C2 beaconing to c2.phantom-net.xyz (87 DNS queries), 
and is actively exfiltrating via HTTPS to the same malicious IP. Account breach confirmed by InsightIDR 
breach monitoring. Immediate containment required.`,

    attack_narrative: `
1. [08:55] Attacker from Tor exit node 185.220.101.47 attempted inbound connection to company 
   external IP on port 4444 (Metasploit default) — blocked by firewall (47 attempts observed).

2. [09:02] AsyncRAT binary (svchost32.exe) and loader DLL (update_helper.dll) were executed 
   on JCARTER-LAPTOP from the user's Temp directory. Both files unsigned, confirmed malicious 
   by VirusTotal (58/64 and 2/64 engines respectively). MITRE techniques: T1059.001, T1547.001, 
   T1071.001, T1095, T1027 (RAT), T1574.002, T1055 (DLL loader).

3. [09:01] JCARTER-LAPTOP (10.0.1.45) began C2 callbacks to 185.220.101.47 on port 443/8443 — 
   ALLOWED by firewall. 87 DNS queries to c2.phantom-net.xyz confirmed beaconing pattern. 
   Domain was previously linked to this Tor IP via passive DNS.

4. [09:10-09:12] Attacker used the established C2 channel context to conduct O365 credential 
   attack from the same Tor IP — 14 failed password attempts followed by 2 MFA failures, 
   then successful authentication at 09:12:45Z.

5. [09:12] Account fully compromised. john.carter is a Domain Admin (groups: Domain Admins, 
   IT-Infrastructure) with confirmed breach status in InsightIDR. Asset JCARTER-LAPTOP 
   has 2 unpatched exploitable CVEs (CVE-2024-21412 CVSS 8.1, CVE-2024-30051 CVSS 7.8) 
   that may have been used for initial access/privilege escalation.

NOTE: Tool limit reached (10/10). get_asset_login_history, get_asset_alert_history, 
and search_process_logs were not called — manual review recommended for lateral movement 
from this asset.`,

    affected_entities: {
        users: ["john.carter", "john.carter@company.com", "COMPANY\\jcarter"],
        assets: ["JCARTER-LAPTOP", "10.0.1.45"],
        ips: ["185.220.101.47"],
    },

    mitre_techniques: [
        "T1078",        // Valid Accounts (compromised admin)
        "T1110.001",    // Brute Force: Password Guessing
        "T1059.001",    // Command and Scripting: PowerShell
        "T1547.001",    // Boot/Logon Autostart: Registry Run Keys
        "T1071.001",    // Application Layer Protocol: Web (C2 over HTTPS)
        "T1095",        // Non-Application Layer Protocol
        "T1027",        // Obfuscated Files or Information
        "T1574.002",    // DLL Side-Loading
        "T1055",        // Process Injection
        "T1041",        // Exfiltration Over C2 Channel
    ],

    recommended_actions: [
        "IMMEDIATE: Disable john.carter AD account and revoke all active O365 sessions",
        "IMMEDIATE: Isolate JCARTER-LAPTOP from network (trigger MDE device isolation)",
        "IMMEDIATE: Block 185.220.101.47 and the entire 185.220.100.0/22 range on all firewalls",
        "IMMEDIATE: Block DNS resolution for c2.phantom-net.xyz and update.totally-legit-cdn.com",
        "HIGH: Reset john.carter credentials and all service accounts with shared passwords",
        "HIGH: Audit all actions taken by john.carter in O365 admin portal since 09:12Z",
        "HIGH: Check Domain Admin group for unauthorized additions made via this account",
        "HIGH: Submit svchost32.exe and update_helper.dll to sandbox for full behavioral analysis",
        "MEDIUM: Apply CVE-2024-21412 and CVE-2024-30051 patches to JCARTER-LAPTOP before re-imaging",
        "MEDIUM: Review get_asset_login_history for lateral movement from JCARTER-LAPTOP (tool limit reached)",
        "MEDIUM: Run search_process_logs for encoded PowerShell execution across all assets in last_7d",
        "LOW: Review Tor exit node block list and ensure all 185.220.100.0/22 is blocked at perimeter",
    ],

    tool_calls_used: 10,
    tool_calls_log: [
        { tool: "check_ip_reputation",         input: { ip: "185.220.101.47" },                                                            status: "ok" },
        { tool: "get_user_activity",            input: { username: "john.carter", time_range: "last_24h" },                                 status: "ok" },
        { tool: "get_user_risk",                input: { username: "john.carter" },                                                         status: "ok" },
        { tool: "search_auth_logs",             input: { username: "john.carter", result_filter: "FAILED", time_range: "last_24h" },        status: "ok" },
        { tool: "get_asset_profile",            input: { identifier: "JCARTER-LAPTOP" },                                                    status: "ok" },
        { tool: "check_file_hash",              input: { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", filename: "svchost32.exe" },       status: "ok" },
        { tool: "check_file_hash",              input: { hash: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f", filename: "update_helper.dll" },   status: "ok" },
        { tool: "search_dns_logs",              input: { hostname: "JCARTER-LAPTOP", time_range: "last_24h" },                              status: "ok" },
        { tool: "search_network_flows",         input: { src_ip: "10.0.1.45", dst_ip: "185.220.101.47", time_range: "last_24h" },          status: "ok" },
        { tool: "get_asset_vulnerabilities",    input: { identifier: "JCARTER-LAPTOP" },                                                    status: "ok" },
        // ↑ limit hit here — get_asset_alert_history, get_asset_login_history,
        //   list_available_logs, search_logs, search_process_logs NOT called
    ],

    raw_llm_response: "[ JSON object above — the actual Claude response would be this as a raw string ]",
};

// ── 4. Mock Conversation Trace (the messages[] array) ─────────
// Shows exactly what the agentic loop looks like turn by turn

export const mockConversationTrace = [
    {
        turn: 1,
        role: "user",
        content: "[ buildInvestigationContext(mockEnrichedInvestigation) output — see below ]",
    },
    {
        turn: 2,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "External IP 185.220.101.47 in two different alerts — check reputation first before anything else.",
        tool_calls: [
            { name: "check_ip_reputation", input: { ip: "185.220.101.47" } },
        ],
    },
    {
        turn: 3,
        role: "user",
        content: "[ tool_result: check_ip_reputation → malicious, Tor, AsyncRAT-C2 ]",
    },
    {
        turn: 4,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "IP confirmed malicious. User john.carter is the actor — get full timeline and risk profile in parallel.",
        tool_calls: [
            { name: "get_user_activity", input: { username: "john.carter", time_range: "last_24h" } },
            { name: "get_user_risk",     input: { username: "john.carter" } },
        ],
    },
    {
        turn: 5,
        role: "user",
        content: "[ tool_results: get_user_activity + get_user_risk → Domain Admin, BREACHED ]",
    },
    {
        turn: 6,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "Admin account, breach confirmed. Confirm auth failure pattern and check asset. Two calls in parallel.",
        tool_calls: [
            { name: "search_auth_logs",  input: { username: "john.carter", result_filter: "FAILED", time_range: "last_24h" } },
            { name: "get_asset_profile", input: { identifier: "JCARTER-LAPTOP" } },
        ],
    },
    {
        turn: 7,
        role: "user",
        content: "[ tool_results: 14 failed + success pattern confirmed. Asset is High criticality. ]",
    },
    {
        turn: 8,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "MDE alert has two file hashes. Check both in parallel — svchost32.exe name is suspicious (masquerading).",
        tool_calls: [
            { name: "check_file_hash", input: { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", filename: "svchost32.exe" } },
            { name: "check_file_hash", input: { hash: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f", filename: "update_helper.dll" } },
        ],
    },
    {
        turn: 9,
        role: "user",
        content: "[ tool_results: svchost32.exe = AsyncRAT (58/64 malicious). dll = AsyncRAT.Loader (suspicious). ]",
    },
    {
        turn: 10,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "RAT confirmed. Check DNS for beaconing and network flows for C2 traffic from the laptop. Parallel.",
        tool_calls: [
            { name: "search_dns_logs",      input: { hostname: "JCARTER-LAPTOP", time_range: "last_24h" } },
            { name: "search_network_flows", input: { src_ip: "10.0.1.45", dst_ip: "185.220.101.47", time_range: "last_24h" } },
        ],
        note: "toolCallCount = 8 after this turn",
    },
    {
        turn: 11,
        role: "user",
        content: "[ tool_results: 87 DNS queries to c2.phantom-net.xyz. Outbound HTTPS to malicious IP confirmed allowed. ]",
    },
    {
        turn: 12,
        role: "assistant",
        stop_reason: "tool_use",
        reasoning: "Need to check asset CVEs — if SmartScreen bypass is unpatched it explains initial execution. One more call.",
        tool_calls: [
            { name: "get_asset_vulnerabilities", input: { identifier: "JCARTER-LAPTOP" } },
        ],
        note: "toolCallCount = 9 before, becomes 10 after execution. LIMIT HIT.",
    },
    {
        turn: 13,
        role: "user",
        content: `[
  { type: "tool_result", content: "[ CVE-2024-21412 + CVE-2024-30051 both exploitable ]" },
  { type: "text", text: "You have now used 10 tool calls (the maximum). Do not call any more tools. Based on everything gathered, produce your final JSON report now." }
]`,
        note: "Results + stop instruction sent in same turn — Claude gets full vuln data before being told to stop.",
    },
    {
        turn: 14,
        role: "assistant",
        stop_reason: "end_turn",
        content: "[ Final JSON report — matches expectedInvestigationReport above ]",
    },
];

// ── 5. buildInvestigationContext output (what the first user message looks like) ──

export const mockContextPrompt = `
## Investigation
ID: inv-phantom-admin-001
Title: SA - Multiple login failures from same user - O365
Priority: HIGH | Status: OPEN
Created: 2026-04-30T09:15:00.000Z
Assignee: SOC Tier 1 (soc-tier1@company.com)

## Pipeline Meta
Total alerts: 3 | Fetched: 3
All evidence fetched successfully

## Alerts & Evidence

### Alert: SA - Multiple login failures from same user - O365
Source: Attacker Behavior Analytics | Created: 2026-04-30T09:14:00.000Z
Fetch status: ok
  Evidence 1 — event_type: ingress_auth
    timestamp: 2026-04-30T09:10:23.000Z
    result/action: FAILED_BAD_PASSWORD
    service: o365
    actor.user: John Carter
    actor.account: john.carter@company.com
    actor.ip: 185.220.101.47
    geo: Frankfurt, Germany (Tor Project)
    detection_context: {"user":{"user_age_mins":525600},"account":{"account_age_mins":525600}}
  Evidence 2 — event_type: ingress_auth
    timestamp: 2026-04-30T09:12:45.000Z
    result/action: SUCCESS
    service: o365
    actor.user: John Carter
    actor.account: john.carter@company.com
    actor.ip: 185.220.101.47
    geo: Frankfurt, Germany (Tor Project)

### Alert: Microsoft Defender for Endpoint - Custom Alert
Source: Attacker Behavior Analytics | Created: 2026-04-30T09:05:00.000Z
Fetch status: ok
  Evidence 1 — event_type: third_party_alert
    timestamp: 2026-04-30T09:02:11.000Z
    result/action: high
    actor.user: john.carter
    actor.asset: JCARTER-LAPTOP
    file_indicators:
      - svchost32.exe | sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709
      - update_helper.dll | sha256: aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f | sha1: b6589fc6ab0dc82cf12099d1c2d40ab994e8410c

### Alert: SA - Excessive Firewall denies from Remote Source IP
Source: Attacker Behavior Analytics | Created: 2026-04-30T08:58:00.000Z
Fetch status: ok
  Evidence 1 — event_type: firewall
    timestamp: 2026-04-30T08:55:12.000Z
    result/action: DENY
    service: tcp/4444
    actor.ip: 185.220.101.47
    network: 185.220.101.47 → 203.0.113.55:4444 (tcp) | status: DENY | observed: 47x
  Evidence 2 — event_type: firewall
    timestamp: 2026-04-30T09:01:00.000Z
    result/action: ALLOW
    service: HTTPS
    actor.asset: JCARTER-LAPTOP
    actor.ip: 10.0.1.45
    network: 10.0.1.45 → 185.220.101.47:443 (tcp) | status: ALLOW | observed: 12x
`.trim();