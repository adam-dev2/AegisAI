import express from 'express';
import authRoutes from './modules/auth/auth.routes.js'

const app = express();
app.use(express.json())
app.get('/',(req,res) => {
    return res.status(200).json({
        status:'ok',
        healthy:true
    })
})
app.use('/api/v1/auth',authRoutes);

export default app;