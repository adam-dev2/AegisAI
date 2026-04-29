import express from 'express';
import authRoutes from './modules/auth/auth.routes.js'
import siemRoutes from './modules/siem/siem.routes.js'
import alertsRoutes from './modules/alerts/alerts.routes.js'
import investigationRoutes from './modules/investigation/investigation.routes.js'

const app = express();
app.use(express.json())
app.get('/',(req,res) => {
    return res.status(200).json({
        status:'ok',
        healthy:true
    })
})
app.use('/api/v1/auth',authRoutes);
app.use('/api/v1/siem',siemRoutes);
app.use('/api/v1/investigation',investigationRoutes);
app.use('/api/v1/alerts',alertsRoutes)

export default app;