import mongoose from 'mongoose';
import "dotenv/config";

const mongoUri = process.env.MONGO_URI;

const connectDB = async () => {
    try {
        await mongoose.connect(mongoUri, {
        });
        console.log("MongoDB connected");
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

export default connectDB;