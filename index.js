const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = 3000;

// Supabase Setup
const supabaseUrl = "SUPABASE_URL";
const supabaseKey = "SUPABASE_KEY";
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = "secret_key";

// Routes
// Register
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to Supabase
    const { data, error } = await supabase
        .from("users")
        .insert([{ username, email, password: hashedPassword }]);

    if (error) return res.status(400).json({ error: error.message });

    res.status(201).json({ message: "User registered successfully!" });
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Fetch user from Supabase
    const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

    if (error) return res.status(400).json({ error: "User not found!" });

    // Check password
    const validPassword = await bcrypt.compare(password, data.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid password!" });

    // Generate JWT
    const token = jwt.sign({ id: data.id, email: data.email }, SECRET_KEY, {
        expiresIn: "1h",
    });

    res.json({ message: "Login successful!", token });
});

// Start server locally
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
