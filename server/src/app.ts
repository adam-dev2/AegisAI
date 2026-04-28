import express from 'express';
import authRoutes from './modules/auth/auth.routes.js'

const app = express();

app.use('/api/v1/auth',authRoutes);

export default app;