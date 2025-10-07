const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');

// Import Routes
const authRoutes = require('./routes/authRoutes');
const musicRoutes = require('./routes/musicRoutes');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors()); // Allow cross-origin requests
app.use(express.json()); // Body parser for JSON
app.use(express.urlencoded({ extended: true })); // Body parser for form data

// **Database Connection**
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected Successfully.'))
    .catch(err => console.error('DB Connection Error:', err));

// **Static Folder for Music Files**
// Jo bhi files /server/uploads mein hongi woh http://localhost:5000/uploads/ se access hongi
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Routes Setup
app.use('/api/admin', authRoutes);
app.use('/api/music', musicRoutes);

// Server Start
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
