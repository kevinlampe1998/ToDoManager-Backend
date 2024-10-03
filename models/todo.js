import mongoose from "mongoose";

const toDoSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: { type: String, required: true, unique: false },
    description: String,
    completed: { type: Boolean, default: false }
});

export default mongoose.model('ToDo', toDoSchema);