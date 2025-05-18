import app from './app.js';
import dotenv from 'dotenv';
import { dbConnect } from './services/prisma.service.js';

dotenv.config();

const PORT = process.env.PORT;

const server = app.listen(PORT, async () => {
    await dbConnect();
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
    });
});
