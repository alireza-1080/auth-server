import app from './app.js';
import dotenv from 'dotenv';
import { dbConnect } from './services/prisma.service.js';

dotenv.config();

const PORT = process.env.PORT;

app.listen(PORT, async () => {
    await dbConnect();
    console.log(`Server is running on http://localhost:${PORT}`);
});
