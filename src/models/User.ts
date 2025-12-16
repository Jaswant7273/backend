import mongoose from "mongoose";

export interface IUser extends mongoose.Document {
  name: string;
  email: string;
  password: string; // hashed
  verified: boolean;
  createdAt: Date;
}

const userSchema = new mongoose.Schema<IUser>({
  name: String,
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: { type: String, required: true },
  createdAt: { type: Date, default: () => new Date() },
  verified: { type: Boolean, default: false },
});

export const User = mongoose.model<IUser>("User", userSchema);
