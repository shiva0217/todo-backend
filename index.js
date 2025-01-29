// Node.js Backend API for Todo Web Application

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'your_jwt_secret';

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/todoApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const TaskSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  userId: String,
  description: String,
  status: { type: String, default: 'pending' },
});

const User = mongoose.model('User', UserSchema);
const Task = mongoose.model('Task', TaskSchema);

// Middleware
app.use(cors());
app.use(express.json());

// Helper: Authenticate Token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes

// Signup
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
    });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Error registering user' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get Profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ name: user.name, email: user.email });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update Profile
app.put('/profile', authenticateToken, async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const updates = { name, email };
    if (password) updates.password = await bcrypt.hash(password, 10);

    const user = await User.findOneAndUpdate({ id: req.user.id }, updates, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get Tasks
app.get('/tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.id });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Create Task
app.post('/tasks', authenticateToken, async (req, res) => {
  const { description } = req.body;

  try {
    const task = new Task({
      id: uuidv4(),
      userId: req.user.id,
      description,
    });
    await task.save();
    res.status(201).json({ message: 'Task created successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to create task' });
  }
});

// Update Task
app.put('/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { description, status } = req.body;

  try {
    const task = await Task.findOneAndUpdate(
      { id, userId: req.user.id },
      { description, status },
      { new: true }
    );
    if (!task) return res.status(404).json({ error: 'Task not found' });

    res.json({ message: 'Task updated successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to update task' });
  }
});

// Delete Task
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const task = await Task.findOneAndDelete({ id, userId: req.user.id });
    if (!task) return res.status(404).json({ error: 'Task not found' });

    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to delete task' });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
