const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();
const port = 5000;

// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());
app.use(
  session({
    secret: "my-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    },
  })
);

// MySQL connection
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "api"
});
//connection checking
connection.connect((err) => {
    if (err) {
        console.error("Error connecting to MySQL:", err);
        return;
    }
    console.log("Connected to MySQL database");
});

app.post("/insert", async (req, res) => {

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";

    connection.query(sql, [name, email, hashedPassword], (err, result) => {
        if (err) {
            console.error("Error inserting data:", err);
            res.status(500).json({ error: "Error inserting data" });
        } else {
            res.status(200).json({ message: "Data inserted successfully" });
        }
    });

});

app.get("/select", (req, res) => {
    const sql = "SELECT * FROM users";
    connection.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching users:", err);
            res.status(500).json({ error: "Error fetching users" });
        } else {
            res.status(200).json(results);
        }
    });
});
app.put("/update/:id", async (req, res) =>{
    const { id } = req.params;
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?";

    connection.query(sql, [name, email, hashedPassword, id], (err, result) => {
        if (err) {
            console.error("Error updating user:", err);
            res.status(500).json({ error: "Error updating user" });
        } else {
            res.status(200).json({ message: "User updated successfully" });
        }
    });
});


app.delete("/delete/:id", (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM users WHERE id = ?";   
     connection.query(sql, [id], (err, result) => {
        if (err) {
            console.error("Error deleting user:", err); 
            res.status(500).json({ error: "Error deleting user" });
        } else {
            res.status(200).json({ message: "User deleted successfully" });
        }
    });
});
// login 
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ?";

    connection.query(sql, [email], async (err, results) => {
        if (err) {
            console.error("Error fetching user:", err);
            return res.status(500).json({ error: "Error fetching user" });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid password" });
        }

        req.session.user = user;
        return res.status(200).json({ message: "Login successful" });
    });
});

// log out
app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error logging out:", err);
            return res.status(500).json({ error: "Error logging out" });
        }

        return res.status(200).json({ message: "Logout successful" });
    });
});
const server = app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}
)
