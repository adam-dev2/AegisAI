## Backend Guide for AegisAI

### 1. What this backend does

This backend is an Express/TypeScript API for an AI SOC agent system. It provides:
- SIEM integration with Rapid7
- Investigation processing and enrichment
- Feedback collection
- Report generation
- Webhook intake from Rapid7
- Background job orchestration (placeholder queue)
- Anthropic Claude AI orchestration for investigation analysis

---

## 2. Core structure

### Entry point
- `src/app.ts`
  - sets up Express
  - registers route groups:
    - `/api/v1/auth`
    - `/api/v1/siem`
    - `/api/v1/investigation`
    - `/api/v1/alerts`
    - `/api/v1/reports`
    - `/api/v1/feedback`
    - `/api/v1/webhooks`

---

## 3. How a request flows

1. **Client request** hits a route in `app.ts`
2. Route is handled by a file in `src/modules/.../*.routes.ts`
3. Router calls a controller in `*.controller.ts`
4. Controller validates input and calls a service in `*.service.ts`
5. Service does database work or API calls
6. Controller sends JSON response

This is the standard MVC flow used across the backend.

---

## 4. Key backend modules

### Feedback
- `src/modules/feedback/feedback.service.ts`
  - database operations for feedback
- `src/modules/feedback/feedback.controller.ts`
  - handles POST and GET requests
- `src/modules/feedback/feedback.routes.ts`
  - exposes:
    - `POST /api/v1/feedback`
    - `GET /api/v1/feedback/:investigation_id`
    - `GET /api/v1/feedback/:investigation_id/stats`

### Investigation
- `src/modules/investigation/investigation.routes.ts`
- `src/modules/investigation/investigation.controllers.ts`
- `src/modules/investigation/investigation.services.ts`
- `src/modules/investigation/report.generator.ts`
  - builds structured investigation reports
- `src/modules/investigation/enrichment.service.ts`
  - enriches investigation data with extra context

### Jobs
- `src/jobs/enrichment.job.ts`
  - runs enrichment on an investigation context file
- `src/jobs/investigation.job.ts`
  - fetches a Rapid7 investigation and processes it
- `src/jobs/notification.job.ts`
  - placeholder notification processing
- `src/config/queue.ts`
  - in-memory job queue implementation
- `src/config/redis.ts`
  - placeholder Redis config for future queueing

### Webhooks
- `src/middleware/webhook.verify.ts`
  - validates Rapid7 webhook signatures
- `src/modules/alerts/webhook.handler.ts`
  - processes webhook event payloads
- `src/modules/alerts/webhook.routes.ts`
  - exposes webhook endpoint:
    - `POST /api/v1/webhooks/rapid7`

---

## 5. Investigation + AI flow

This backend stores investigation context into JSON files like:
- `context-<investigation_id>.json`

Then the AI agent loads that file and runs analysis using Claude. The basic flow:
- Rapid7 data is fetched
- alerts and evidence are normalized
- the investigation context is written to a file
- Claude is called with tools and context to analyze the incident

---

## 6. How to work on it

### Modify an existing feature
1. Find the route in `src/modules/<feature>/<feature>.routes.ts`
2. Change behavior in the controller `*.controller.ts`
3. Update business logic in `*.service.ts`
4. Rebuild with:
   - `cd server && npm run build`

### Add a new route
1. Add new controller function in the correct module
2. Add new service function if needed
3. Add the route path in `*.routes.ts`
4. Register the route in `src/app.ts` if it is a new module
5. Build and test

### Add new queue/job behavior
1. Add a new job handler in `src/jobs/`
2. Add queue entry in `src/config/queue.ts`
3. Add call sites from webhook or controller to queue jobs

### Debugging
- Use logs in `src/lib/logger.ts`
- If TypeScript fails, fix imports or types first
- Route params should use `String(req.params.x || '')` because TS strict mode needs strings

---

## 7. What to check next

If you want to change behavior:
- `feedback` → check `src/modules/feedback/*`
- `reports` → check `src/modules/investigation/report.generator.ts`
- `webhooks` → check `src/modules/alerts/webhook.*`
- `job processing` → check `src/config/queue.ts` and `src/jobs/*.ts`

---

## 8. Practical examples

### Example: Add a new feedback field
- update `feedback.service.ts` INSERT columns
- update `feedback.controller.ts` validation
- update DB schema if needed
- rebuild

### Example: Update webhook event handling
- change logic in `src/modules/alerts/webhook.handler.ts`
- update route payload validation in `webhook.routes.ts`
- redeploy

---

## 9. Recommended workflow

1. Make changes
2. Run `cd server && npm run build`
3. If available, run tests
4. Use Postman or frontend requests to verify the new endpoint
5. Inspect logs for errors

---

## 10. One last tip

Keep the pattern:
- routes only wire endpoints
- controllers validate and orchestrate
- services do the real work
- jobs handle background tasks

That separation makes it much easier to change behavior safely.