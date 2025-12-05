require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const userModel = require("./models/User.js");

const app = express();

// Middlewares
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_URL, 
    credentials: true,
  })
);

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.log("DB Connection Error:", err));

const JWT_SECRET = process.env.JWT_SECRET;

// Authentication Middleware
const requireAuth = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) return res.status(401).json("Not authenticated");

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json("Invalid token");

    req.user = decoded;
    next();
  });
};

// ======================== ROUTES ===========================

// Register
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await userModel.findOne({ email });
    if (existingUser) return res.json("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);

    await userModel.create({ email, password: hashedPassword });

    res.json("User registered successfully");
  } catch (err) {
    console.log(err);
    res.status(500).json("Server error");
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) return res.json("User not found");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json("Incorrect Email or Password");

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,        // for HTTPS
      sameSite: "none",    // needed for cross-site cookies
    });

    res.json("Successfully Logged in");
  } catch (err) {
    console.log(err);
    res.status(500).json("Server error");
  }
});

// Get Logged in User
app.get("/me", requireAuth, async (req, res) => {
  const user = await userModel.findById(req.user.id).select("-password");
  res.json(user);
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.json("Logged out");
});

// =================== NEWS API ROUTE ======================

// Fetch Top Headlines
app.get("/news", async (req, res) => {
  try {
    const { category, q } = req.query;

    const BASE_URL = "https://newsapi.org/v2";
    const API_KEY = process.env.NEWSAPI_KEY;

    let url = "";

    // 1️⃣ VALID NEWSAPI CATEGORIES
    const VALID_CATEGORIES = [
      "business",
      "entertainment",
      "general",
      "health",
      "science",
      "sports",
      "technology",
    ];

    // 2️⃣ If category is valid → top-headlines with category
    if (category && VALID_CATEGORIES.includes(category.toLowerCase())) {
      url = `${BASE_URL}/top-headlines?country=in&category=${category}&pageSize=100&apiKey=${API_KEY}`;
    }

    // 3️⃣ If search query exists → everything endpoint
    else if (q) {
      url = `${BASE_URL}/everything?q=${encodeURIComponent(
        q
      )}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
    }

    // 4️⃣ If category is Timeline → breaking news logic
    else if (category === "timeline") {
      const timelineQuery = "breaking OR latest OR update OR news";
      url = `${BASE_URL}/everything?q=${encodeURIComponent(
        timelineQuery
      )}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
    }

    // 5️⃣ If category is Startups
    else if (category === "startups") {
      const startupQuery =
        "startup OR funding OR venture OR investor OR incubator OR founders OR unicorn";
      url = `${BASE_URL}/everything?q=${encodeURIComponent(
        startupQuery
      )}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
    }

    // 6️⃣ If category is Markets
    else if (category === "markets") {
      const marketQuery =
        "market OR stock OR nifty OR sensex OR NSE OR BSE OR inflation OR economy";
      url = `${BASE_URL}/everything?q=${encodeURIComponent(
        marketQuery
      )}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
    }

    // 7️⃣ Default (All) → top headlines
    else {
      url = `${BASE_URL}/top-headlines?country=in&pageSize=100&apiKey=${API_KEY}`;
    }

    const response = await axios.get(url);

    res.json(response.data);
  } catch (err) {
    console.log("News API Error:", err);
    res.status(500).json("Failed to fetch news");
  }
});


// ============================================================

app.listen(process.env.PORT || 3001, () => {
  console.log(`Server running on port ${process.env.PORT || 3001}`);
});
