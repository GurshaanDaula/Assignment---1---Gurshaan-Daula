const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
require('dotenv').config();
console.log('MongoDB URI:', process.env.MONGODB_URI); // This will show the value loaded from .env

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Setup MySQL connection (Safe - Using environment variables)
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: false
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL Database!');
});

// MongoDB URI from .env file
const mongoURI = process.env.MONGODB_URI;

// Connect to MongoDB using MongoClient
MongoClient.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(client => {
        console.log('Connected to MongoDB');
        
        // Setup secure session with MongoDB store
        app.use(session({
            secret: process.env.SESSION_SECRET || 'supersecretkey',
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({
                mongoUrl: process.env.MONGODB_URI
            }),
            cookie: {
                httpOnly: true,
                secure: false, // Set to true only if using HTTPS
                maxAge: 3600000 // Session expires in 1 hour
            }
        }));
        
        
        // Routes below...

        // Home route
        app.get('/', (req, res) => {
            res.render('home', { username: req.session.username || null });
        });

        // Signup page
        app.get('/signup', (req, res) => {
            res.render('signup', { error: req.query.error || null });
        });

        // Signup route (Using safe_users table)
        app.post('/signup', (req, res) => {
            const { username, password } = req.body;
            if (!username || !password) {
                return res.redirect('/signup?error=Missing%20fields');
            }

            // Hash the password before storing
            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) throw err;
                let sql = 'INSERT INTO safe_users (username, password) VALUES (?, ?)';
                db.query(sql, [username, hashedPassword], (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.redirect('/signup?error=Username%20already%20exists');
                        }
                        throw err;
                    }
                    req.session.username = username;
                    res.redirect('/members');
                });
            });
        });

        // Login page
        app.get('/login', (req, res) => {
            res.render('login', { error: req.query.error || null });
        });

        app.post('/login', (req, res) => {
            const { username, password } = req.body;

            // Query database using parameterized query to prevent SQL injection
            let sql = 'SELECT * FROM safe_users WHERE username = ?';
            db.query(sql, [username], (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.redirect('/login?error=Database%20error');
                }

                if (results.length > 0) {
                    bcrypt.compare(password, results[0].password, (err, match) => {
                        if (err) {
                            console.error('Bcrypt error:', err);
                            return res.redirect('/login?error=Server%20error');
                        }

                        if (match) {
                            // Set session data
                            req.session.username = username;
                            req.session.save((err) => {
                                if (err) {
                                    console.error('Session save error:', err);
                                    return res.redirect('/login?error=Session%20save%20failed');
                                }
                                console.log('Session saved, redirecting to /members');
                                return res.redirect('/members'); // Redirect to members page
                            });
                        } else {
                            return res.redirect('/login?error=Invalid%20credentials');
                        }
                    });
                } else {
                    return res.redirect('/login?error=Invalid%20credentials');
                }
            });
        });

        // Members page
        app.get('/members', (req, res) => {
            if (!req.session.username) {
                console.log('No session found, redirecting to home');
                return res.redirect('/');
            }
            res.render('members', { username: req.session.username });
        });

        // Logout
        app.get('/logout', (req, res) => {
            // Destroy the session
            req.session.destroy((err) => {
                if (err) {
                    console.log('Error destroying session:', err);
                    return res.redirect('/members');
                }
        
                // Redirect to the home page after session is destroyed
                res.redirect('/');
            });
        });

        // 404 page
        app.use((req, res) => {
            res.status(404).render('404');
        });

        // Start server
        app.listen(3000, () => {
            console.log('Server running on http://localhost:3000');
        });
    })
    .catch(err => {
        console.error('Failed to connect to MongoDB:', err);
    });
