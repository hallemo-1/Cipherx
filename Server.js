process.on("uncaughtException", (err) => {
    console.log("Error caught:", err);
});
const forge = require("node-forge");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path =require("path")
const jwt = require("jsonwebtoken");

function encrypt(text, shift = 3) {
    return text.split("").map(c =>
        String.fromCharCode(c.charCodeAt(0) + shift)
    ).join("");
}

function decrypt(text, shift = 3) {
    return text.split("").map(c =>
        String.fromCharCode(c.charCodeAt(0) - shift)
    ).join("");
}

const app = express();
app.use(express.static(__dirname));
const PORT = 3000;

app.use(cors());
app.use(express.json());

// إنشاء الداتابيز
const db = new sqlite3.Database("./users.db");


// إنشاء جدول لو مش موجود
 
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    publicKey TEXT,
    privateKey TEXT
)
`);

 db.run(`
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    message TEXT
)
`);
// register
 app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const keypair = forge.pki.rsa.generateKeyPair(2048);

    const publicKey = forge.pki.publicKeyToPem(keypair.publicKey);
    const privateKey = forge.pki.privateKeyToPem(keypair.privateKey);
    // Validation
    if (!username || !password) {
        return res.send("كل الحقول مطلوبة ❌");
    }

    if (password.length < 6) {
        return res.send("الباسورد لازم يكون 6 حروف على الأقل ❌");
    }

    // check لو اليوزر موجود
    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (user) {
                return res.send("اليوزر موجود بالفعل ❌");
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.run(
                 "INSERT INTO users (username, password, publicKey, privateKey) VALUES (?, ?, ?, ?)",
                    [username, hashedPassword, publicKey, privateKey],
                (err) => {
                    if (err) return res.send("Error ❌");

                    res.send("User Registered 🔐");
                }
            );
        }
    );
});

// login
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err) return res.send("Error ❌");

            if (!user) {
                return res.send("User not found ❌");
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {

                // إنشاء التوكن
                const token = jwt.sign(
                    { username: user.username },
                    "secretkey",
                    { expiresIn: "1h" }
                );

                res.send({
                    message: "Login Successful ✅",
                    token: token
                });

            } else {
                res.send("Wrong Password ❌");
            }
        }
    );
});

app.get("/profile", authenticateToken, (req, res) => {
    res.send({
        message: "Welcome 🔥",
        user: req.user
    });
});
app.get("/profile", authenticateToken, (req, res) => {
    db.get(
        "SELECT id, username FROM users WHERE username = ?",
        [req.user.username],
        (err, user) => {
            if (err) return res.send("Error ❌");

            if (!user) return res.send("User not found ❌");

            res.send(user);
        }
    );
});
app.post("/change-password", authenticateToken, (req, res) => {
    const { oldPassword, newPassword } = req.body;
if (!newPassword || newPassword.length < 6) {
    return res.send("الباسورد الجديد ضعيف ❌");
}
    db.get(
        "SELECT * FROM users WHERE username = ?",
        [req.user.username],
        async (err, user) => {
            if (err) return res.send("Error ❌");

            if (!user) return res.send("User not found ❌");

            const isMatch = await bcrypt.compare(oldPassword, user.password);

            if (!isMatch) {
                return res.send("Old password غلط ❌");
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

            db.run(
                "UPDATE users SET password = ? WHERE username = ?",
                [hashedPassword, req.user.username],
                (err) => {
                    if (err) return res.send("Error ❌");

                    res.send("Password updated 🔐");
                }
            );
        }
    );
});
 app.post("/send", authenticateToken, (req, res) => {
    const { message, to } = req.body;

    db.get(
        "SELECT publicKey FROM users WHERE username = ?",
        [to],
        (err, user) => {

            if (err) return res.send("Error ❌");
            if (!user) return res.send("User not found ❌");

            const publicKey = forge.pki.publicKeyFromPem(user.publicKey);

            const encrypted = publicKey.encrypt(message, "RSA-OAEP");

            const encoded = forge.util.encode64(encrypted);

            db.run(
                "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                [req.user.username, to, encoded],
                () => res.send("Encrypted Message Sent 🔐")
            );
        }
    );
});
 
app.get("/messages", authenticateToken, (req, res) => {

    db.get(
        "SELECT privateKey FROM users WHERE username = ?",
        [req.user.username],
        (err, user) => {

            if (err) return res.send("Error ❌");
            if (!user) return res.send("User not found ❌");

            const privateKey = forge.pki.privateKeyFromPem(user.privateKey);

            db.all(
                "SELECT * FROM messages WHERE receiver = ?",
                [req.user.username],
                (err, rows) => {

                    const messages = rows.map(m => {
                        try {
                            const decrypted = privateKey.decrypt(
                                forge.util.decode64(m.message),
                                "RSA-OAEP"
                            );

                            return {
                                from: m.sender,
                                message: decrypted
                            };

                        } catch (e) {
                            return {
                                from: m.sender,
                                message: "❌ رسالة غير قابلة لفك التشفير"
                            };
                        }
                    });

                    res.json(messages);
                }
            );
        }
    );
});

 app.listen(PORT, () => {
    console.log("Server شغال 🔥");
});
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.send("Access Denied ❌");
    }

    jwt.verify(token, "secretkey", (err, user) => {
        if (err) {
            return res.send("Invalid Token ❌");
        }

        req.user = user;
        next();
    });
}