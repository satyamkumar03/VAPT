// server.js - 5-Step Exploit Chain Demo (OWASP WSTG & OWASP Top 10)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setup In-Memory Database (A02:2021 - Cryptographic Failures)
// Passwords stored in plaintext instead of secure hashes
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'super_secret_master_99', 'admin')");
    db.run("INSERT INTO users VALUES (2, 'john_doe', 'user123pass', 'user')");
    
    db.run("CREATE TABLE catalog (id INT, name TEXT)");
    db.run("INSERT INTO catalog VALUES (1, 'Standard Subscription')");
});

// -------------------------------------------------------------------
// STEP 1: RECON (WSTG-CONF-04 | A05:2021 - Security Misconfiguration)
// Unreferenced legacy API route left exposed in production
// -------------------------------------------------------------------
app.get('/api/v1/legacy-search', (req, res) => {
    const query = req.query.q;
    if (!query) return res.json({ hint: "Use ?q= to search the catalog" });

    // ---------------------------------------------------------------
    // STEP 2: INJECTION (WSTG-INPV-05 | A03:2021 - Injection [SQLi])
    // Unparameterized SQLite query allows database dumping
    // ---------------------------------------------------------------
    const sql = `SELECT * FROM catalog WHERE name = '${query}'`;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// -------------------------------------------------------------------
// STEP 3: INITIAL ACCESS (WSTG-CRYP-04 | A02:2021 - Cryptographic Failures)
// Attacker logs in using the plaintext password extracted via SQLi
// -------------------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
        if (user) {
            res.json({ status: "success", user: { id: user.id, username: user.username, role: user.role } });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    });
});

// -------------------------------------------------------------------
// STEP 4: PRIVILEGE ESCALATION (WSTG-BUSL-01 | A01:2021 - Broken Access Control)
// Mass Assignment: Blindly trusting the 'role' field in the JSON body
// -------------------------------------------------------------------
app.post('/api/user/update', (req, res) => {
    const { id, username, role } = req.body;
    const sql = `UPDATE users SET role = '${role || 'user'}' WHERE id = ${id}`;
    db.run(sql, (err) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        res.json({ message: "Profile updated successfully!", newRole: role || 'user' });
    });
});

// -------------------------------------------------------------------
// STEP 5: IMPACT & RCE (WSTG-INPV-12 | A03:2021 - Injection [OS Command])
// Newly promoted admin executes arbitrary OS commands
// -------------------------------------------------------------------
app.post('/admin/system-ping', (req, res) => {
    const { host, role } = req.body;
    if (role !== 'admin') return res.status(403).json({ error: "Admin role required" });

    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.json({ output: stdout || err.message });
    });
});

// Start Server
app.listen(3000, () => {
    console.log('OWASP Demo running on http://localhost:3000');
    console.log('Target system is ready for chained exploitation.');
});
