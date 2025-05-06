import express, { Response, ErrorRequestHandler } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import apiRoute from './routes/api.route.js';

const app = express();

app.use(cors());
app.use(cookieParser());
app.use(helmet());

// Configure JSON parsing with error handling
app.use(
    express.json({
        verify: (req, res: Response, buf) => {
            try {
                JSON.parse(buf.toString());
            } catch (error: unknown) {
                if (error instanceof Error) {
                    res.status(400).json({
                        status: 'error',
                        message: 'Invalid JSON',
                    });
                }
                throw new Error('Invalid JSON');
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
const errorHandler: ErrorRequestHandler = (err, _req, res: Response) => {
    console.error(err.stack);
    res.status(err.status || 500).json({
        status: 'error',
        message: err.message || 'Internal server error',
    });
};

app.use(errorHandler);

export default app;
