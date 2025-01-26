import express from 'express';
import authRouter from './routes/authRouter.js';
import cors from 'cors';
import cookieParser from 'cookie-parser';

//^ Create an Express app
const app = express();

//^ Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());

//^ Routes
app.use("/api/auth", authRouter);

export default app;