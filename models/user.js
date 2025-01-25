import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required'],
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: [true, 'Username is already taken'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: [true, 'Email is already taken'],
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
    enum: ['admin', 'user'],
  },
},
{
  timestamps: true,
});

const userModel = mongoose.model('User', userSchema);

export default userModel;