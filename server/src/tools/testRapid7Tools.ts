import { executeRapid7Tool } from "./rapid7Tools.js";
import fs from 'fs';

type ToolTestMap = Record<string, any>;

const TOOL_TESTS: ToolTestMap = {
    search_logs: {
        leql_query: 'where(result="FAILED") groupby(source_address)',
        log_name: "Asset Authentication",
        time_range: "last_24h",
        limit: 10,
    },

    search_auth_logs: {
        username: "local.admin@safeaeon.com",
        result_filter: "FAILED",
        time_range: "last_24h",
        limit: 10,
    },

    search_process_logs: {
        hostname: "Siddh-SOC482",
        process_name: "consent.exe",
        time_range: "last_24h",
        limit: 10,
    },

    search_dns_logs: {
        queried_domain: "safeaeon.com",
        time_range: "last_24h",
        limit: 10,
    },

    search_network_flows: {
        src_ip: "3.16.213.130",
        time_range: "last_24h",
        limit: 10,
    },

    get_user_activity: {
        username: "local.admin@safeaeon.com",
        time_range: "last_7d",
    },

    get_user_risk: {
        username: "local.admin@safeaeon.com",
    },

    get_asset_profile: {
        identifier: "Siddh-SOC482",
        time_range: "last_24h",
    },

    get_asset_alert_history: {
        identifier: "Siddh-SOC482",
        time_range: "last_7d",
    },

    get_asset_login_history: {
        hostname: "Siddh-SOC482",
        time_range: "last_24h",
        result_filter: "ALL",
    },

    get_asset_vulnerabilities: {
        identifier: "64.71.176.252",
        min_cvss: 7,
    },

    list_available_logs: {},

    check_ip_reputation: {
        ip: "3.16.213.130",
    },

    check_file_hash: {
        hash: "44d88612fea8a8f36de82e1278abb02f", // EICAR test hash
    },
};

const results:any[] = [];

async function runTests() {
    console.log("Starting Rapid7 Tool Tests...\n");


    for (const [toolName, input] of Object.entries(TOOL_TESTS)) {
        console.log("====================================");
        console.log(`Running: ${toolName}`);
        console.log("Input:", JSON.stringify(input, null, 2));

        try {
            const start = Date.now();
            let resultObj = {
                toolname:"",
                duration:0,
                output:""
            };

            const result = await executeRapid7Tool(toolName, input);
            const duration = Date.now() - start;
            
            console.log(`Success (${duration} ms)`);

            resultObj.toolname =toolName;
            resultObj.duration =duration;
            resultObj.output = result;
            results.push(resultObj);
            console.log(
                "Output:",
                JSON.stringify(result, null, 2).slice(0, 2000)
            );
        } catch (err: any) {
            console.error(`Error in ${toolName}:`);
            console.error(err?.message || err);
        }

        console.log("====================================\n");
    }

    console.log("All tests completed.");
    fs.writeFileSync('TestingResults.json',JSON.stringify(results,null,2));
}

runTests().catch((err) => {
    console.error("Fatal Error:", err);
});