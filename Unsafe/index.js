// Unsafe Version - index.js
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const MongoStore = require('connect-mongo');
require('dotenv').config();
const app = express();

app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Setup MySQL connection (Unsafe - No environment variables, hardcoded credentials)
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: true
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL Database!');
});

// Setup MongoDB session storage
const mongoUri = process.env.MONGODB_URI;
const store = MongoStore.create({
    mongoUrl: mongoUri,
    collectionName: 'sessions'
});

// Setup session (Unsafe - No encryption)
app.use(session({
    secret: 'secretkey',
    resave: false,
    saveUninitialized: true,
    store: store,  // Store sessions in MongoDB
    cookie: {
        httpOnly: true,  // Prevents XSS attacks
        secure: false,   // Set to true if using HTTPS
        maxAge: 3600000  // Session expires in 1 hour
    }
}));

// Home route
app.get('/', (req, res) => {
    res.render('home', { username: req.session.username || null });
});

// Signup page
app.get('/signup', (req, res) => {
    res.render('signup', { error: req.query.error || null });
});

// Signup route (Unsafe - No validation, direct query with user input)
app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.redirect('/signup?error=Missing%20fields');
    }

    let sql = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;
    db.query(sql, (err) => {
        if (err) throw err;
        req.session.username = username;
        res.redirect('/members');
    });
});

// Login page
app.get('/login', (req, res) => {
    res.render('login', { error: req.query.error || null });
});

// Login route (Unsafe - No hashing, vulnerable to SQL Injection)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    let sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(sql, (err, results) => {
        if (err) throw err;
        console.log(results);
        if (results.length > 0) {
            req.session.username = username;
            res.redirect('/members');
        } else {
            res.redirect('/login?error=Invalid%20credentials');
        }
    });
});

// Members page
app.get('/members', (req, res) => {
    if (!req.session.username) return res.redirect('/');
    res.render('members', { username: req.session.username });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404 page
app.use((req, res) => {
    res.status(404).render('404');
});

// Start server
app.listen(3000, () => {
    console.log('Unsafe Server running on http://localhost:3000');
});
