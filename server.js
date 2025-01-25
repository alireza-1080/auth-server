import app from './app.js';
import "dotenv/config";
import connectDB from './configs/db.js';

const port = process.env.PORT;

//^ Connect to MongoDB
connectDB();

//^ Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});