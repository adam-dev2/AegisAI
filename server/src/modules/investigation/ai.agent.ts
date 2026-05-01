// ============================================================
// LLM Orchestrator — SOC Investigation Analysis Loop
//
// Flow:
//   EnrichedInvestigation
//     → build prompt
//     → Claude (with tools)
//     → tool call → execute → result back to Claude
//     → repeat until stop_reason="end_turn" or tool limit hit
//     → final InvestigationReport returned to caller
// ============================================================

import Anthropic from "@anthropic-ai/sdk";
import { rapid7ToolDefinitions, executeRapid7Tool } from "../../tools/rapid7Tools.js";
import { logger } from "../../lib/logger.js";
import type { EnrichedInvestigation } from "../../types/alert.types.js";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY! });

const MODEL = "claude-sonnet-4-5";
const MAX_TOOL_CALLS = 10;

// ── Output Types ──────────────────────────────────────────────

export interface InvestigationReport {
    investigation_id: string;
    title: string;
    priority: string;

    // LLM's final structured assessment
    verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN" | "NEEDS_REVIEW";
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
    confidence: "HIGH" | "MEDIUM" | "LOW";
    summary: string;                    // 2-3 sentence executive summary
    attack_narrative: string;           // what happened, in order
    affected_entities: {
        users: string[];
        assets: string[];
        ips: string[];
    };
    mitre_techniques: string[];         // e.g. ["T1078", "T1110.001"]
    recommended_actions: string[];      // ordered by priority
    tool_calls_used: number;
    tool_calls_log: ToolCallRecord[];
    raw_llm_response: string;           // final text from Claude
}

interface ToolCallRecord {
    tool: string;
    input: Record<string, any>;
    status: "ok" | "error";
    error?: string;
}

// ── System Prompt ─────────────────────────────────────────────

const SYSTEM_PROMPT = `You are an expert SOC (Security Operations Center) analyst AI.
You are given a security investigation from Rapid7 InsightIDR with pre-fetched alert evidence.
Your job is to analyze the investigation, use tools to gather additional context, and produce a final structured report.

## Investigation Process

1. Read the investigation context carefully — alerts, event types, actors, IPs, files
2. Identify what you need to confirm or rule out (e.g. is this IP malicious? is this a real user?)
3. Use tools strategically — do not call the same tool twice with the same parameters
4. After gathering enough context (or hitting the tool limit), produce your final report

## Tool Usage Rules

- ALWAYS check IP reputation for any external IP in firewall or auth events
- ALWAYS check file hashes for any SHA256/SHA1 found in endpoint alerts
- For user-based alerts: start with get_user_activity, then get_user_risk
- For asset-based alerts: start with get_asset_profile
- Use search_auth_logs / search_network_flows to confirm patterns you see in evidence
- Max 10 tool calls total — be efficient, prioritize the highest-signal lookups first

## Final Report Format

When done investigating, respond with a JSON object ONLY (no markdown, no preamble):

{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN" | "NEEDS_REVIEW",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "summary": "2-3 sentence executive summary for a SOC manager",
  "attack_narrative": "Step-by-step description of what happened in chronological order",
  "affected_entities": {
    "users": ["list of affected usernames or emails"],
    "assets": ["list of affected hostnames or IPs"],
    "ips": ["list of suspicious external IPs"]
  },
  "mitre_techniques": ["T1078", "T1110.001"],
  "recommended_actions": ["Ordered list of actions for the SOC team"]
}`;

// ── Context Builder ───────────────────────────────────────────
// Converts EnrichedInvestigation → concise LLM prompt
// Strips RRNs and internal IDs — LLM doesn't need them
// Keeps raw_source off the prompt — too large, tools fetch detail on demand

function buildInvestigationContext(inv: EnrichedInvestigation): string {
    const d = inv.details;

    const lines: string[] = [
        `## Investigation`,
        `ID: ${inv.investigation_id}`,
        `Title: ${d.title ?? "Unknown"}`,
        `Priority: ${d.priority ?? "Unknown"} | Status: ${d.status ?? "Unknown"}`,
        `Created: ${d.created_time ?? "Unknown"}`,
        `Assignee: ${d.assignee?.name ?? "Unassigned"} (${d.assignee?.email ?? ""})`,
        "",
        `## Pipeline Meta`,
        `Total alerts: ${inv.pipeline_meta.total_alerts} | Fetched: ${inv.pipeline_meta.alerts_fetched}`,
        inv.pipeline_meta.evidence_failures.length > 0
            ? `Evidence fetch failures: ${inv.pipeline_meta.evidence_failures.join(", ")}`
            : "All evidence fetched successfully",
        "",
        `## Alerts & Evidence`,
    ];

    for (const alert of inv.alerts) {
        lines.push(`### Alert: ${alert.alert_type}`);
        lines.push(`Source: ${alert.alert_source} | Created: ${alert.created_time}`);
        lines.push(`Fetch status: ${alert.fetch_status}`);

        if (alert.evidences.length === 0) {
            lines.push("  No evidence available");
            continue;
        }

        for (const [i, ev] of alert.evidences.entries()) {
            lines.push(`  Evidence ${i + 1} — event_type: ${ev.event_type}`);
            lines.push(`    timestamp: ${ev.timestamp ?? "unknown"}`);
            lines.push(`    result/action: ${ev.result ?? "N/A"}`);
            lines.push(`    service: ${ev.service ?? "N/A"}`);

            // Actor
            const actor = ev.actor;
            if (actor.user)    lines.push(`    actor.user: ${actor.user}`);
            if (actor.account) lines.push(`    actor.account: ${actor.account}`);
            if (actor.asset)   lines.push(`    actor.asset: ${actor.asset}`);
            if (actor.ip)      lines.push(`    actor.ip: ${actor.ip}`);

            // Geo
            if (ev.geo) {
                lines.push(`    geo: ${ev.geo.city ?? ""}, ${ev.geo.country ?? ""} (${ev.geo.org ?? ""})`);
            }

            // Network (firewall)
            if (ev.network) {
                const n = ev.network;
                lines.push(`    network: ${n.src_ip} → ${n.dst_ip}:${n.dst_port} (${n.protocol}) | status: ${ev.result} | observed: ${n.observation_count}x`);
            }

            // File indicators (MDE)
            if (ev.file_indicators && ev.file_indicators.length > 0) {
                lines.push(`    file_indicators:`);
                for (const f of ev.file_indicators) {
                    lines.push(`      - ${f.filename} | sha256: ${f.sha256 ?? "N/A"} | sha1: ${f.sha1 ?? "N/A"}`);
                }
            }

            // Detection context (user/account age etc.)
            if (ev.detection_context) {
                lines.push(`    detection_context: ${JSON.stringify(ev.detection_context)}`);
            }
        }
        lines.push("");
    }

    return lines.join("\n");
}

// ── Tool Call Executor ────────────────────────────────────────

async function executeTool(
    toolName: string,
    toolInput: Record<string, any>,
    log: ToolCallRecord[]
): Promise<string> {
    logger.info(`[LLM] Tool call: ${toolName} | input: ${JSON.stringify(toolInput)}`);
    try {
        const result = await executeRapid7Tool(toolName, toolInput);
        log.push({ tool: toolName, input: toolInput, status: "ok" });

        // Truncate large results before sending back to LLM
        // — events arrays can be massive, cap at 20 items
        if (result?.events && Array.isArray(result.events)) {
            result.events = result.events.slice(0, 20);
        }

        return JSON.stringify(result, null, 2);
    } catch (err: any) {
        const errMsg = err?.message ?? "Unknown error";
        logger.warn(`[LLM] Tool ${toolName} failed: ${errMsg}`);
        log.push({ tool: toolName, input: toolInput, status: "error", error: errMsg });
        return JSON.stringify({ error: errMsg, tool: toolName });
    }
}

// ── Parse Final Report ────────────────────────────────────────
// Claude returns JSON — extract it cleanly even if it adds prose

function parseFinalReport(text: string): Omit<InvestigationReport, "investigation_id" | "title" | "priority" | "tool_calls_used" | "tool_calls_log" | "raw_llm_response"> | null {
    // Strip markdown code fences if present
    const cleaned = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();

    // Find the outermost JSON object
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start === -1 || end === -1) return null;

    try {
        return JSON.parse(cleaned.slice(start, end + 1));
    } catch {
        logger.warn("[LLM] Failed to parse final report JSON");
        return null;
    }
}

// ── Main Orchestrator Loop ────────────────────────────────────

export async function analyzeInvestigation(inv: EnrichedInvestigation): Promise<InvestigationReport> {
    const investigationContext = buildInvestigationContext(inv);
    const toolCallLog: ToolCallRecord[] = [];
    let toolCallCount = 0;

    logger.info(`[LLM] Starting analysis for investigation ${inv.investigation_id}`);

    // Conversation history — grows as tools are called and results returned
    const messages: Anthropic.MessageParam[] = [
        {
            role: "user",
            content: `Please analyze this security investigation and use the available tools to gather additional context before producing your final report.\n\n${investigationContext}`,
        },
    ];

    let finalText = "";
    let continueLoop = true;

    // ── Agentic Loop ──────────────────────────────────────────
    while (continueLoop) {
        const response = await anthropic.messages.create({
            model: MODEL,
            max_tokens: 4096,
            system: SYSTEM_PROMPT,
            tools: rapid7ToolDefinitions as Anthropic.Tool[],
            messages,
        });

        logger.info(`[LLM] Response — stop_reason: ${response.stop_reason} | content blocks: ${response.content.length}`);

        // Collect text from this response turn
        const textBlocks = response.content.filter((b) => b.type === "text");
        if (textBlocks.length > 0) {
            finalText = textBlocks.map((b: any) => b.text).join("\n");
        }

        // ── Case 1: LLM is done ───────────────────────────────
        if (response.stop_reason === "end_turn") {
            continueLoop = false;
            break;
        }

        // ── Case 2: LLM wants to use tools ───────────────────
        if (response.stop_reason === "tool_use") {
            const toolUseBlocks = response.content.filter((b) => b.type === "tool_use");

            // Execute all tool calls in this turn in parallel
            // Always finish the current batch — even if it pushes past the limit
            const toolResults = await Promise.all(
                toolUseBlocks.map(async (block: any) => {
                    toolCallCount++;
                    const resultText = await executeTool(block.name, block.input, toolCallLog);
                    return {
                        type: "tool_result" as const,
                        tool_use_id: block.id,
                        content: resultText,
                    };
                })
            );

            messages.push({ role: "assistant", content: response.content });

            // After finishing the batch, check if we've hit the limit
            // If yes — send results + stop instruction together in one user turn
            if (toolCallCount >= MAX_TOOL_CALLS) {
                logger.warn(`[LLM] Tool limit reached (${toolCallCount}/${MAX_TOOL_CALLS}) — sending results then forcing final report`);
                messages.push({
                    role: "user",
                    content: [
                        ...toolResults,
                        {
                            type: "text",
                            text: `You have now used ${toolCallCount} tool calls (the maximum). Do not call any more tools. Based on everything gathered, produce your final JSON report now.`,
                        },
                    ],
                });
                // One more LLM turn for the report — loop continues but Claude
                // has been told not to call tools, so next stop_reason will be end_turn
                continue;
            }

            messages.push({ role: "user", content: toolResults });
            logger.info(`[LLM] Tool calls so far: ${toolCallCount}/${MAX_TOOL_CALLS}`);
            continue;
        }

        // ── Case 3: Unexpected stop reason ───────────────────
        logger.warn(`[LLM] Unexpected stop_reason: ${response.stop_reason} — breaking loop`);
        continueLoop = false;
    }

    // ── Parse and build final report ──────────────────────────
    const parsed = parseFinalReport(finalText);

    const report: InvestigationReport = {
        investigation_id: inv.investigation_id,
        title: inv.details?.title ?? "Unknown",
        priority: inv.details?.priority ?? "Unknown",
        verdict:              parsed?.verdict              ?? "NEEDS_REVIEW",
        severity:             parsed?.severity             ?? "LOW",
        confidence:           parsed?.confidence           ?? "LOW",
        summary:              parsed?.summary              ?? finalText.slice(0, 500),
        attack_narrative:     parsed?.attack_narrative     ?? "",
        affected_entities:    parsed?.affected_entities    ?? { users: [], assets: [], ips: [] },
        mitre_techniques:     parsed?.mitre_techniques     ?? [],
        recommended_actions:  parsed?.recommended_actions  ?? [],
        tool_calls_used: toolCallCount,
        tool_calls_log: toolCallLog,
        raw_llm_response: finalText,
    };

    logger.info(
        `[LLM] Analysis complete for ${inv.investigation_id} — verdict: ${report.verdict} | tools used: ${toolCallCount}/${MAX_TOOL_CALLS}`
    );

    return report;
}

// ── Batch Runner ──────────────────────────────────────────────
// Called by processInvestigation after enrichment pipeline completes

export async function analyzeInvestigations(
    investigations: EnrichedInvestigation[]
): Promise<InvestigationReport[]> {
    logger.info(`[LLM] Analyzing ${investigations.length} investigations`);

    // Run sequentially — one investigation at a time to avoid Claude rate limits
    // Switch to Promise.all with p-limit if you need parallel processing later
    const reports: InvestigationReport[] = [];
    for (const inv of investigations) {
        try {
            const report = await analyzeInvestigation(inv);
            reports.push(report);
        } catch (err: any) {
            logger.error(`[LLM] Failed to analyze investigation ${inv.investigation_id}: ${err.message}`);
            // Push a failed placeholder so the caller still gets a result for every investigation
            reports.push({
                investigation_id: inv.investigation_id,
                title: inv.details?.title ?? "Unknown",
                priority: inv.details?.priority ?? "Unknown",
                verdict: "NEEDS_REVIEW",
                severity: "LOW",
                confidence: "LOW",
                summary: `Analysis failed: ${err.message}`,
                attack_narrative: "",
                affected_entities: { users: [], assets: [], ips: [] },
                mitre_techniques: [],
                recommended_actions: ["Manual review required — automated analysis failed"],
                tool_calls_used: 0,
                tool_calls_log: [],
                raw_llm_response: "",
            });
        }
    }

    logger.info(`[LLM] Batch complete — ${reports.length} reports generated`);
    return reports;
}