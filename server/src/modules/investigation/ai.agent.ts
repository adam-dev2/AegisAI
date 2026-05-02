import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { logger } from '../../lib/logger.js';
import { AppError } from '../../lib/AppError.js';
import { ANTHROPIC_API_KEY, ANTHROPIC_API_URL, ANTHROPIC_MODEL } from '../../config/env.js';
import { executeRapid7Tool, rapid7ToolDefinitions } from '../../tools/queryRapid7.js';

const ANTHROPIC_ENABLED = Boolean(ANTHROPIC_API_KEY);

interface AgentRequest {
  investigation_id?: string;
  investigation_context?: any;
  question: string;
  max_steps?: number;
}

interface ToolAction {
  tool: string;
  input: any;
  result: any;
  error?: string;
}

function toClaudeToolDefinitions() {
  return rapid7ToolDefinitions.map((tool) => ({
    name: tool.name,
    description: tool.description,
    type: 'structured',
    parameters: tool.input_schema,
  }));
}

function summarizeContext(context: any): string {
  if (!context) return 'No investigation context provided.';

  const investigationId = context.investigation_id ?? context.id ?? 'unknown';
  const alertCount = Array.isArray(context.alerts) ? context.alerts.length : 0;
  const createdTime = context.details?.created_time ?? context.details?.created_at ?? 'unknown';
  const title = context.details?.title ?? context.details?.InvestigationName ?? 'unknown';

  const alertsSummary = Array.isArray(context.alerts)
    ? context.alerts
        .slice(0, 4)
        .map((alert: any, index: number) => `  ${index + 1}. ${alert.alert_type ?? alert.alert_source ?? 'unknown'} (id=${alert.alert_id ?? alert.id ?? 'n/a'})`) 
        .join('\n')
    : '  no alerts available';

  return `Investigation ID: ${investigationId}\nTitle: ${title}\nCreated: ${createdTime}\nAlerts: ${alertCount}\nTop alerts:\n${alertsSummary}`;
}

async function loadInvestigationContext(investigationId: string): Promise<any> {
  const filePath = path.resolve(process.cwd(), `context-${investigationId}.json`);
  if (!fs.existsSync(filePath)) {
    throw new AppError(`Investigation context file not found for id ${investigationId}`, 404);
  }

  const raw = await fs.promises.readFile(filePath, 'utf8');
  return JSON.parse(raw);
}

async function callAnthropic(messages: any[]) {
  if (!ANTHROPIC_ENABLED) {
    throw new AppError('ANTHROPIC_API_KEY is required to run the AI agent', 500);
  }

  const requestBody = {
    model: ANTHROPIC_MODEL,
    messages,
    temperature: 0.2,
    max_tokens_to_sample: 800,
    tools: toClaudeToolDefinitions(),
    tool_invocation: 'auto',
  };

  const response = await axios.post(
    ANTHROPIC_API_URL,
    requestBody,
    {
      headers: {
        Authorization: `Bearer ${ANTHROPIC_API_KEY}`,
        'Content-Type': 'application/json',
      },
      timeout: 60000,
    }
  );

  return response.data;
}

function formatToolResult(result: any): string {
  if (result === undefined || result === null) return 'null';
  if (typeof result === 'string') return result;
  try {
    return JSON.stringify(result, null, 2);
  } catch {
    return String(result);
  }
}

export async function runAgentAnalysis(request: AgentRequest) {
  const { investigation_id, investigation_context, question } = request;
  const maxSteps = Math.min(6, Math.max(1, request.max_steps ?? 3));

  let context = investigation_context;
  if (!context && investigation_id) {
    context = await loadInvestigationContext(investigation_id);
  }

  const contextSummary = summarizeContext(context);

  const messages: any[] = [
    {
      role: 'system',
      content: `You are an AI SOC Analyst. Use only the available tools and the provided investigation context to answer user questions. If you need additional data from Rapid7, call a tool. Avoid hallucination and do not invent investigation details. The agent may use any of the provided Rapid7 tools to inspect logs, users, assets, or vulnerability posture.`,
    },
    {
      role: 'user',
      content: `Investigation context:\n${contextSummary}\n\nContext payload:\n${context ? JSON.stringify(context, null, 2) : 'none'}\n\nQuestion: ${question}`,
    },
  ];

  const toolActions: ToolAction[] = [];

  for (let step = 0; step < maxSteps; step += 1) {
    const anthropicResponse = await callAnthropic(messages);
    const choice = anthropicResponse?.choices?.[0];
    const message = choice?.message;

    if (!message) {
      throw new AppError('No response from Anthropic model', 500);
    }

    const toolInvocation = message.tool_invocation ?? message.function_call ?? choice?.tool_invocation;
    if (toolInvocation) {
      const toolName = toolInvocation.name;
      let toolInput: any = {};

      try {
        toolInput = toolInvocation.arguments
          ? JSON.parse(toolInvocation.arguments)
          : {};
      } catch (err: any) {
        throw new AppError(`Failed to parse tool arguments: ${err.message}`, 500);
      }

      const toolAction: ToolAction = {
        tool: toolName,
        input: toolInput,
        result: null,
      };

      try {
        const result = await executeRapid7Tool(toolName, toolInput);
        toolAction.result = result;
        messages.push({
          role: 'assistant',
          content: null,
          tool_invocation: {
            name: toolName,
            arguments: JSON.stringify(toolInput),
          },
        });
        messages.push({
          role: 'tool',
          name: toolName,
          content: formatToolResult(result),
        });
      } catch (err: any) {
        toolAction.error = String(err?.message ?? err);
        messages.push({
          role: 'assistant',
          content: null,
          tool_invocation: {
            name: toolName,
            arguments: JSON.stringify(toolInput),
          },
        });
        messages.push({
          role: 'tool',
          name: toolName,
          content: `ERROR: ${toolAction.error}`,
        });
      }

      toolActions.push(toolAction);
      continue;
    }

    const finalText = message.content ?? '';
    return {
      investigation_id,
      question,
      answer: finalText,
      tool_actions: toolActions,
      raw_response: anthropicResponse,
    };
  }

  const timeoutMessage = 'Maximum agent steps reached without a final answer.';
  messages.push({ role: 'assistant', content: timeoutMessage });
  return {
    investigation_id,
    question,
    answer: timeoutMessage,
    tool_actions: toolActions,
    raw_response: null,
  };
}
