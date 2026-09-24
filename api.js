// ===============================
// IMPORT PACKAGES
// ===============================
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");


// ===============================
// CREATE EXPRESS APP
// ===============================
const app = express();
const port = 5000;


// ===============================
// MIDDLEWARE
// ===============================

// Allow React frontend to communicate with this backend
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// Allow JSON data from Postman or React
app.use(express.json());

// Allow form data
app.use(express.urlencoded({ extended: true }));


// ===============================
// SESSION CONFIGURATION
// ===============================

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


// ===============================
// MYSQL DATABASE CONNECTION
// ===============================

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "api",
});


// Connect to MySQL
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }

  console.log("Connected to MySQL database");
});


// ===============================
// CREATE USER
// POST /insert
// ===============================

app.post("/insert", async (req, res) => {
  const { name, email, password } = req.body;

  // Check required fields
  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required",
    });
  }

  try {
    // Encrypt password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users (name, email, password)
      VALUES (?, ?, ?)
    `;

    connection.query(
      sql,
      [name, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error("Error inserting user:", err);

          return res.status(500).json({
            error: "Error inserting user",
          });
        }

        return res.status(201).json({
          message: "User created successfully",
          insertedId: result.insertId,
        });
      }
    );
  } catch (error) {
    console.error("Error:", error);

    return res.status(500).json({
      error: "Server error",
    });
  }
});


// ===============================
// GET ALL USERS
// GET /select
// ===============================

app.get("/select", (req, res) => {
  const sql = "SELECT id, name, email FROM users";

  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching users:", err);

      return res.status(500).json({
        error: "Error fetching users",
      });
    }

    return res.status(200).json(results);
  });
});


// ===============================
// UPDATE USER
// PUT /update/:id
// ===============================

app.put("/update/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  // Check required fields
  if (!name || !email) {
    return res.status(400).json({
      error: "Name and email are required",
    });
  }

  try {
    let sql;
    let params;

    // If password is provided, update password too
    if (password && password.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password, 10);

      sql = `
        UPDATE users
        SET name = ?, email = ?, password = ?
        WHERE id = ?
      `;

      params = [name, email, hashedPassword, id];
    } else {
      // Update only name and email
      sql = `
        UPDATE users
        SET name = ?, email = ?
        WHERE id = ?
      `;

      params = [name, email, id];
    }

    connection.query(sql, params, (err, result) => {
      if (err) {
        console.error("Error updating user:", err);

        return res.status(500).json({
          error: "Error updating user",
        });
      }

      return res.status(200).json({
        message: "User updated successfully",
      });
    });
  } catch (error) {
    console.error("Update error:", error);

    return res.status(500).json({
      error: "Server error",
    });
  }
});


// ===============================
// DELETE USER
// DELETE /delete/:id
// ===============================

app.delete("/delete/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM users WHERE id = ?";

  connection.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting user:", err);

      return res.status(500).json({
        error: "Error deleting user",
      });
    }

    return res.status(200).json({
      message: "User deleted successfully",
    });
  });
});


// ===============================
// LOGIN
// POST /login
// ===============================

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Check required fields
  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  // Find user by email
  const sql = "SELECT * FROM users WHERE email = ?";

  connection.query(sql, [email], async (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);

      return res.status(500).json({
        error: "Error fetching user",
      });
    }

    // Check if user exists
    if (results.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    const user = results[0];

    // Compare entered password with encrypted password
    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    // Wrong password
    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Invalid password",
      });
    }

    // Save user information in session
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
    };

    return res.status(200).json({
      message: "Login successful",
      user: req.session.user,
    });
  });
});


// ===============================
// LOGOUT
// POST /logout
// ===============================

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error logging out:", err);

      return res.status(500).json({
        error: "Error logging out",
      });
    }

    return res.status(200).json({
      message: "Logout successful",
    });
  });
});


// ===============================
// START SERVER
// ===============================

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
