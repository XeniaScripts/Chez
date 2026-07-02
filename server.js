const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
// Render sets process.env.PORT automatically. Default to 3000 if running locally.
const PORT = process.env.PORT || 3000;

// 1. DATABASE SETUP & DIRECTORY CHECK
// Define the directory path where the database will live
const dataDir = '/data';

// Check if the /data folder exists. If it doesn't, create it dynamically.
// This prevents the SQLITE_CANTOPEN crash seen in your logs.
if (!fs.existsSync(dataDir)) {
    try {
        fs.mkdirSync(dataDir, { recursive: true });
        console.log(`Successfully created directory at: ${dataDir}`);
    } catch (err) {
        console.warn(`Could not create ${dataDir}, falling back to local directory.`);
    }
}

// Determine safe database file location based on folder availability
const usePersistentStorage = fs.existsSync(dataDir);
const dbPath = usePersistentStorage 
    ? path.resolve(dataDir, 'database.sqlite')
    : path.resolve(__dirname, 'database.sqlite');

console.log(`Initializing SQLite database file at: ${dbPath}`);
const db = new sqlite3.Database(dbPath);

// Initialize the database table structure
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS authorized_users (
            user_id TEXT PRIMARY KEY, 
            access_token TEXT NOT NULL
        )
    `, (err) => {
        if (err) console.error('Error creating database table:', err.message);
        else console.log('Database table structure verified / operational.');
    });
});

// 2. OAUTH2 WEB SERVER REDIRECT CALLBACK
app.get('/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing authorization code from Discord.');

    try {
        // Exchange temporary authorization code for an API Access Token
        const tokenExchange = await axios.post('https://discord.com/api/v10/oauth2/token', 
            new URLSearchParams({
                client_id: process.env.CLIENT_ID,
                client_secret: process.env.CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: process.env.REDIRECT_URI,
            }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const { access_token } = tokenExchange.data;

        // Use the token to fetch the authorizing user's Discord profile details
        const userProfile = await axios.get('https://discord.com/api/v10/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const userId = userProfile.data.id;

        // Securely insert or refresh the user token inside the database
        const query = `INSERT INTO authorized_users (user_id, access_token) VALUES (?, ?)
                       ON CONFLICT(user_id) DO UPDATE SET access_token=excluded.access_token`;

        db.run(query, [userId, access_token], (err) => {
            if (err) {
                console.error('Failed to commit user to database:', err.message);
                return res.status(500).send("Database configuration error saving credentials.");
            }
            res.send("Authorization successful! You can safely close this browser window and return to Discord.");
        });

    } catch (error) {
        console.error('OAuth2 Core Exchange Failed:', error.response?.data || error.message);
        res.status(500).send("Authentication protocol failure. Check your server environment keys.");
    }
});

// 3. SECURE BOT BACKEND ENDPOINT
// This allows the Wispbyte bot instance to fetch the raw database entries over HTTPS
app.get('/api/users', (req, res) => {
    const inboundSecretKey = req.headers['x-secret-key'];
    
    // Verify that the inbound request matches your INTERNAL_SECRET_KEY password
    if (!inboundSecretKey || inboundSecretKey !== process.env.INTERNAL_SECRET_KEY) {
        console.warn(`Unauthorized API download attempt rejected from IP: ${req.ip}`);
        return res.status(403).send('Access Denied: Invalid Secret Key Verification.');
    }

    db.all("SELECT user_id, access_token FROM authorized_users", [], (err, rows) => {
        if (err) {
            console.error('Failed to pull user query array:', err.message);
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Root route to easily check if the Render app is awake and running
app.get('/', (req, res) => {
    res.send('OAuth2 Gateway Web Server Status: ONLINE');
});

// Start the Express network listener
app.listen(PORT, () => {
    console.log(`Web server gateway actively listening on port allocation: ${PORT}`);
});
