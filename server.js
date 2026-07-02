const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Render Disk storage path
const dbPath = path.resolve('/data', 'database.sqlite'); 
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS authorized_users (user_id TEXT PRIMARY KEY, access_token TEXT NOT NULL)`);
});

// OAuth2 Callback
app.get('/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('No code provided.');

    try {
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
        const userProfile = await axios.get('https://discord.com/api/v10/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        db.run(`INSERT INTO authorized_users (user_id, access_token) VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET access_token=excluded.access_token`, 
                [userProfile.data.id, access_token], (err) => {
            if (err) return res.status(500).send("Database save failed.");
            res.send("Authorized successfully! You can safely close this tab.");
        });
    } catch (error) {
        res.status(500).send("Authentication failed.");
    }
});

// Secure API endpoint for the bot to get tokens
app.get('/api/users', (req, res) => {
    const secretKey = req.headers['x-secret-key'];
    if (secretKey !== process.env.INTERNAL_SECRET_KEY) return res.status(403).send('Forbidden');

    db.all("SELECT user_id, access_token FROM authorized_users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(PORT, () => console.log(`Web server live on port ${PORT}`));

