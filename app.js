import express from 'express';
import authRouter from './routes/authRouter.js';

//^ Create an Express app
const app = express();

//^ Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//^ Routes
app.use("/api/auth", authRouter);

export default app;