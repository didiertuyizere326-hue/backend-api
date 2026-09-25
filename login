const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const port = 5000;

// ==========================
// MIDDLEWARE
// ==========================

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// ==========================
// MYSQL CONNECTION
// ==========================

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "api",
});

connection.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
    return;
  }

  console.log("Connected to MySQL database");
});

// ==========================
// REGISTER USER
// ==========================

app.post("/insert", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql =
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";

    connection.query(
      sql,
      [name, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error("Insert error:", err);

          return res.status(500).json({
            error: "Error creating user",
          });
        }

        res.status(201).json({
          message: "User created successfully",
          userId: result.insertId,
        });
      }
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Server error",
    });
  }
});

// ==========================
// LOGIN
// ==========================

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Check input
  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  // Find user
  const sql = "SELECT * FROM users WHERE email = ?";

  connection.query(sql, [email], async (err, results) => {
    if (err) {
      console.error("Database error:", err);

      return res.status(500).json({
        error: "Database error",
      });
    }

    // User doesn't exist
    if (results.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    const user = results[0];

    // Compare password
    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Create session
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
    };

    res.status(200).json({
      message: "Login successful",
      user: req.session.user,
    });
  });
});

// ==========================
// CHECK LOGIN
// ==========================

app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Not logged in",
    });
  }

  res.json({
    user: req.session.user,
  });
});

// ==========================
// LOGOUT
// ==========================

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);

      return res.status(500).json({
        error: "Logout failed",
      });
    }

    res.json({
      message: "Logout successful",
    });
  });
});

// ==========================
// GET ALL USERS
// ==========================

app.get("/select", (req, res) => {
  const sql = "SELECT id, name, email FROM users";

  connection.query(sql, (err, results) => {
    if (err) {
      console.error(err);

      return res.status(500).json({
        error: "Error getting users",
      });
    }

    res.json(results);
  });
});

// ==========================
// UPDATE USER
// ==========================

app.put("/update/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email, password } = req.body;

  if (!name || !email) {
    return res.status(400).json({
      error: "Name and email are required",
    });
  }

  try {
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);

      const sql =
        "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?";

      connection.query(
        sql,
        [name, email, hashedPassword, id],
        (err) => {
          if (err) {
            return res.status(500).json({
              error: "Update failed",
            });
          }

          res.json({
            message: "User updated successfully",
          });
        }
      );
    } else {
      const sql =
        "UPDATE users SET name = ?, email = ? WHERE id = ?";

      connection.query(
        sql,
        [name, email, id],
        (err) => {
          if (err) {
            return res.status(500).json({
              error: "Update failed",
            });
          }

          res.json({
            message: "User updated successfully",
          });
        }
      );
    }
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Server error",
    });
  }
});

// ==========================
// DELETE USER
// ==========================

app.delete("/delete/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM users WHERE id = ?";

  connection.query(sql, [id], (err) => {
    if (err) {
      return res.status(500).json({
        error: "Delete failed",
      });
    }

    res.json({
      message: "User deleted successfully",
    });
  });
});

// ==========================
// START SERVER
// ==========================

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
