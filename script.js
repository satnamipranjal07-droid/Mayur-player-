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
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

// Password ko hash (encrypt) karne ka logic
AdminSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Login ke samay password match karne ka logic
AdminSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('Admin', AdminSchema);
const mongoose = require('mongoose');

const MusicSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    artist: { type: String, required: true, trim: true },
    // fileURL: server par file ka path store karega (e.g., /uploads/1234567.mp3)
    fileURL: { type: String, required: true }, 
    uploadedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Music', MusicSchema);
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

const protect = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            
            // Token verify karein aur payload nikaalein
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // User ID se Admin details fetch karein aur password exclude karein
            req.admin = await Admin.findById(decoded.id).select('-password');
            
            next(); // Agar token valid hai, toh agle function par jaao

        } catch (error) {
            console.error('Token Error:', error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

module.exports = { protect };
const express = require('express');
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

const router = express.Router();

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

// **1. Admin Registration (Testing Only!)**
// Pehla admin banane ke liye iska use karein, phir isko hata dein
router.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const admin = await Admin.create({ username, password });
        res.status(201).json({ token: generateToken(admin._id) });
    } catch (error) {
        res.status(500).json({ message: 'Error creating admin.' });
    }
});

// **2. Admin Login**
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const admin = await Admin.findOne({ username });
        
        if (admin && (await admin.matchPassword(password))) {
            res.json({
                username: admin.username,
                token: generateToken(admin._id),
            });
        } else {
            res.status(401).json({ message: 'Invalid Credentials' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error during login' });
    }
});

module.exports = router;
const express = require('express');
const multer = require('multer');
const path = require('path');
const { protect } = require('../middleware/authMiddleware'); // Security middleware
const Music = require('../models/Music');

const router = express.Router();

// Multer Setup: Local storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); 
    }
});
const upload = multer({ storage: storage });

// **1. Protected Upload Route**
router.post('/upload', protect, upload.single('musicFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file selected.' });
    }
    
    const { title, artist } = req.body;
    
    try {
        const newSong = new Music({
            title,
            artist,
            fileURL: `/uploads/${req.file.filename}`, 
            uploadedBy: req.admin._id, // Protected middleware se aayi hui ID
        });

        const savedSong = await newSong.save();
        res.status(201).json({ message: 'Music uploaded successfully!', song: savedSong });

    } catch (error) {
        res.status(500).json({ message: 'Error saving music details.' });
    }
});

// **2. Public Fetch Songs Route**
router.get('/songs', async (req, res) => {
    try {
        const songs = await Music.find().sort({ createdAt: -1 });
        res.json(songs);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching songs.' });
    }
});

module.exports = router;
// Server ka base URL (jab deploy karenge toh badal jayega)
const API_BASE_URL = 'http://localhost:5000/api';

// --- CHECK LOGIN STATUS ON LOAD ---
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('adminToken');
    const username = localStorage.getItem('adminUsername');
    if (token && username) {
        showAdminPanel(username);
    }
    fetchAndDisplaySongs();
});

function showAdminPanel(username) {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('upload-section').style.display = 'block';
    document.getElementById('admin-name').textContent = username;
}

function logout() {
    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminUsername');
    window.location.reload(); // Page reload karke login form dikhao
}

// --- 1. LOGIN LOGIC ---
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const messageElement = document.getElementById('login-message');

    try {
        const response = await fetch(`${API_BASE_URL}/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('adminToken', data.token);
            localStorage.setItem('adminUsername', data.username);
            showAdminPanel(data.username);
            messageElement.textContent = 'Login Successful!';
            messageElement.style.color = 'green';
        } else {
            messageElement.textContent = data.message || 'Login Failed.';
            messageElement.style.color = 'red';
        }
    } catch (error) {
        messageElement.textContent = 'Error connecting to server.';
        console.error('Login Error:', error);
    }
});

// --- 2. UPLOAD LOGIC ---
document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('adminToken');
    if (!token) return;

    const title = document.getElementById('song-title').value;
    const artist = document.getElementById('artist-name').value;
    const file = document.getElementById('music-file').files[0];
    const messageElement = document.getElementById('upload-message');

    const formData = new FormData();
    formData.append('title', title);
    formData.append('artist', artist);
    formData.append('musicFile', file); // Multer se match karega

    try {
        const response = await fetch(`${API_BASE_URL}/music/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }, // Token bhejna zaruri hai!
            body: formData,
        });

        const data = await response.json();

        if (response.ok) {
            messageElement.textContent = `Upload Successful! ${data.song.title}`;
            document.getElementById('upload-form').reset();
            fetchAndDisplaySongs(); // Naye gaane ko list mein dikhane ke liye
        } else {
            messageElement.textContent = `Upload Failed: ${data.message || 'An error occurred.'}`;
        }
    } catch (error) {
        messageElement.textContent = 'Error connecting to server.';
        console.error('Upload Error:', error);
    }
});

// --- 3. FETCH & DISPLAY SONGS LOGIC ---
async function fetchAndDisplaySongs() {
    try {
        const response = await fetch(`${API_BASE_URL}/music/songs`);
        const songs = await response.json();
        const songListElement = document.getElementById('song-list');
        songListElement.innerHTML = ''; // Purani list saaf karo

        if (songs.length === 0) {
            songListElement.innerHTML = '<p>No songs found. Admin, please upload some!</p>';
            return;
        }

        songs.forEach(song => {
            const songElement = document.createElement('div');
            songElement.className = 'song-card'; // Styling ke liye class
            songElement.innerHTML = `
                <h3>${song.title}</h3>
                <p>Artist: ${song.artist}</p>
                <audio controls src="${API_BASE_URL}${song.fileURL}"></audio>
                <hr>
            `;
            songListElement.appendChild(songElement);
        });

    } catch (error) {
        document.getElementById('song-list').innerHTML = '<p style="color: red;">Failed to load songs from server.</p>';
        console.error('Failed to fetch songs:', error);
    }
}
