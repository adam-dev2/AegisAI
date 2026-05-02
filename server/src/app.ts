import express from 'express';
import authRoutes from './modules/auth/auth.routes.js';
import siemRoutes from './modules/siem/siem.routes.js';
import alertsRoutes from './modules/alerts/alerts.routes.js';
import webhookRoutes from './modules/alerts/webhook.routes.js';
import investigationRoutes from './modules/investigation/investigation.routes.js';
import reportsRoutes from './modules/reports/reports.routes.js';
import feedbackRoutes from './modules/feedback/feedback.routes.js';
import cors from 'cors'

const app = express();
app.use(express.json());
app.use(cors({
  origin:['http://localhost:5173']
}))
app.get('/', (req, res) => {
  return res.status(200).json({
    status: 'ok',
    healthy: true,
  });
});
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/siem', siemRoutes);
app.use('/api/v1/investigation', investigationRoutes);
app.use('/api/v1/alerts', alertsRoutes);
app.use('/api/v1/webhooks', webhookRoutes);
app.use('/api/v1/reports', reportsRoutes);
app.use('/api/v1/feedback', feedbackRoutes);

export default app;
