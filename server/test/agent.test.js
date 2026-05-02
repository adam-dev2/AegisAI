import assert from 'node:assert';
import { rapid7ToolDefinitions, executeRapid7Tool } from '../src/tools/queryRapid7.js';
import { ANTHROPIC_API_KEY } from '../src/config/env.js';
assert(Array.isArray(rapid7ToolDefinitions), 'Rapid7 tool definitions must be an array');
const toolNames = rapid7ToolDefinitions.map((tool) => tool.name);
assert(new Set(toolNames).size === toolNames.length, 'Tool names must be unique');
assert(toolNames.includes('search_logs'), 'search_logs tool must be present');
assert(toolNames.includes('list_available_logs'), 'list_available_logs tool must be present');
let failed = false;
try {
    assert.rejects(async () => executeRapid7Tool('invalid_tool_name', {}), /Unknown Rapid7 tool/, 'dispatcher should reject unknown tools');
}
catch (err) {
    failed = true;
    console.error('Tool dispatcher test failed:', err);
}
if (!failed) {
    console.log('Rapid7 tool registry + dispatcher passed.');
}
if (process.env.TENANT_API_KEY) {
    console.log('TENANT_API_KEY set; checking live Rapid7 list_available_logs call...');
    const result = await executeRapid7Tool('list_available_logs', {});
    assert(Array.isArray(result), 'list_available_logs should return an array');
    console.log(`list_available_logs returned ${result.length} logs.`);
}
else {
    console.log('TENANT_API_KEY not set; skipping live Rapid7 API validation.');
}
if (ANTHROPIC_API_KEY) {
    console.log('ANTHROPIC_API_KEY is configured.');
}
else {
    console.log('ANTHROPIC_API_KEY not set; agent smoke test disabled.');
}
//# sourceMappingURL=agent.test.js.map