import express, { Response, ErrorRequestHandler } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import apiRoute from './routes/api.route.js';
import { ZodError } from 'zod';
import jwt from 'jsonwebtoken';
const { JsonWebTokenError, TokenExpiredError } = jwt;

const app = express();

app.use(cors());
app.use(helmet());

// Configure JSON parsing with error handling
app.use(
    express.json({
        verify: (req, res, buf) => {
            try {
                JSON.parse(buf.toString());
            } catch (e) {
                (res as Response).status(400).json({
                    status: 'error',
                    message: 'Invalid JSON',
                });
                return;
            }
        },
    }),
);

app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.send('Hello World');
});

app.use('/api', apiRoute);

// Catch-all route handler for undefined routes
app.use((_req: express.Request, res: express.Response) => {
    res.status(404).json({
        status: 'error',
        message: 'Route not found',
    });
});

// General error handling middleware
const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
    console.error(err.stack);

    if (err instanceof ZodError) {
        const firstError = err.errors[0];
        const fieldName = firstError.path.join('.');
        let message: string;

        if (firstError.message === 'Required') {
            message = `${fieldName} is required`;
        } else {
            message = firstError.message;
        }

        res.status(400).json({
            status: 'error',
            message,
        });
        return;
    }

    if (err instanceof JsonWebTokenError) {
        res.status(401).json({
            status: 'error',
            message: 'Invalid token',
        });
        return;
    }

    if (err instanceof TokenExpiredError) {
        res.status(401).json({
            status: 'error',
            message: 'Token expired',
        });
        return;
    }

    res.status(err.status || 500).json({
        status: 'error',
        message: err.message || 'Internal server error',
    });
};

app.use(errorHandler);

export default app;
