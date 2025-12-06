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

const FRONTEND_URL = process.env.FRONTEND_URL || "*";
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.log("DB Connection Error:", err));

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

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
    if (!email || !password) return res.status(400).json("Missing fields");

    const existingUser = await userModel.findOne({ email });
    if (existingUser) return res.json("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);

    await userModel.create({ email, password: hashedPassword });

    res.json("User registered successfully");
  } catch (err) {
    // handle duplicate key error more gracefully
    if (err && err.code === 11000) {
      return res.json("User already exists");
    }
    console.log("Register Error:", err);
    res.status(500).json("Server error");
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json("Missing fields");

    const user = await userModel.findOne({ email });
    if (!user) return res.json("User not found");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json("Incorrect Email or Password");

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    // secure cookie only in production
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };

    res.cookie("token", token, cookieOptions);
    res.json("Successfully Logged in");
  } catch (err) {
    console.log("Login Error:", err);
    res.status(500).json("Server error");
  }
});

// Get Logged in User
app.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.log("Me Error:", err);
    res.status(500).json("Server error");
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "none",
  });
  res.json("Logged out");
});

// =================== NEWS API ROUTE (improved, dedupe, category keywords) ======================

app.get("/news", async (req, res) => {
  try {
    const { category, q } = req.query;
    const BASE_URL = "https://newsapi.org/v2";
    const API_KEY = process.env.NEWSAPI_KEY;
    if (!API_KEY) return res.status(500).json({ error: "Missing NEWSAPI_KEY" });

    // focused keywords for categories to reduce overlap
    const CATEGORY_KEYWORDS = {
      technology: [
        "technology",
        "tech",
        "software",
        "gadgets",
        "AI",
        "artificial intelligence",
        "machine learning",
        "mobile",
        "app",
        "semiconductor",
      ],
      sports: [
        "sport",
        "cricket",
        "football",
        "soccer",
        "tennis",
        "IPL",
        "match",
        "tournament",
        "athlete",
        "score",
      ],
      business: [
        "market",
        "stock",
        "finance",
        "economy",
        "investment",
        "IPO",
        "funding",
        "bank",
        "business",
      ],
      entertainment: [
        "entertainment",
        "movie",
        "film",
        "bollywood",
        "hollywood",
        "celebrity",
        "music",
        "tv",
        "series",
      ],
      health: [
        "health",
        "healthcare",
        "medical",
        "medicine",
        "disease",
        "hospital",
        "covid",
        "wellness",
      ],
      science: [
        "science",
        "research",
        "space",
        "NASA",
        "discovery",
        "climate",
        "physics",
        "biology",
      ],
    };

    const buildOrQuery = (arr) => encodeURIComponent(arr.map((s) => `"${s}"`).join(" OR "));

    const dedupeArticles = (articles) => {
      const seenUrls = new Set();
      const seenTitles = new Set();
      const out = [];
      for (const a of articles) {
        if (!a || !a.url) continue;
        const url = a.url.trim();
        const title = (a.title || "").replace(/\s+/g, " ").trim().toLowerCase();
        if (seenUrls.has(url)) continue;
        if (seenTitles.has(title)) continue;
        seenUrls.add(url);
        seenTitles.add(title);
        out.push(a);
      }
      return out;
    };

    let url = "";
    const attempted = [];

    // 1) If explicit search q provided -> search in title first (strong relevance)
    if (q) {
      const qInTitle = encodeURIComponent(q);
      url = `${BASE_URL}/everything?qInTitle=${qInTitle}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
      attempted.push({ reason: `qInTitle=${q}`, url });
    }

    // 2) If category is provided, try focused queries
    if (!q && category) {
      const cat = category.toLowerCase();

      if (Object.prototype.hasOwnProperty.call(CATEGORY_KEYWORDS, cat)) {
        const qStrict = buildOrQuery(CATEGORY_KEYWORDS[cat]);
        url = `${BASE_URL}/everything?qInTitle=${qStrict}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
        attempted.push({ reason: `category strict (${cat})`, url });
      } else {
        // special categories
        if (cat === "startups") {
          const qStartup = encodeURIComponent("startup OR funding OR venture OR investor OR unicorn");
          url = `${BASE_URL}/everything?q=${qStartup}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
          attempted.push({ reason: "startups", url });
        } else if (cat === "markets") {
          const qMarket = encodeURIComponent("market OR stock OR nifty OR sensex OR economy");
          url = `${BASE_URL}/everything?q=${qMarket}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
          attempted.push({ reason: "markets", url });
        } else if (cat === "timeline") {
          const qTimeline = encodeURIComponent("breaking OR latest OR update OR news");
          url = `${BASE_URL}/everything?q=${qTimeline}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
          attempted.push({ reason: "timeline", url });
        } else {
          // fallback general
          url = `${BASE_URL}/everything?q=news&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
          attempted.push({ reason: "default everything", url });
        }
      }
    }

    // 3) If nothing chosen yet, default to recent news
    if (!url) {
      url = `${BASE_URL}/everything?q=news&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
      attempted.push({ reason: "default everything", url });
    }

    // Fetch primary attempt
    const response = await axios.get(url);
    let articles = (response.data && response.data.articles) || [];

    // If primary attempt returns too few results (< 6) and we used strict title search, try broader query
    if (articles.length < 6) {
      const lastAttempt = attempted[attempted.length - 1];
      if (lastAttempt && lastAttempt.reason.includes("strict") && category) {
        try {
          const cat = category.toLowerCase();
          const broaderQ = encodeURIComponent(CATEGORY_KEYWORDS[cat].join(" OR "));
          const fallbackUrl = `${BASE_URL}/everything?q=${broaderQ}&language=en&sortBy=publishedAt&pageSize=100&apiKey=${API_KEY}`;
          const r2 = await axios.get(fallbackUrl);
          const art2 = (r2.data && r2.data.articles) || [];
          if (art2.length > articles.length) {
            attempted.push({ reason: "fallback broader", url: fallbackUrl });
            articles = art2;
          }
        } catch (e) {
          // ignore fallback errors
        }
      }
    }

    // Deduplicate
    const cleaned = dedupeArticles(articles);

    // Return cleaned articles
    return res.json({
      status: "ok",
      totalResults: cleaned.length,
      articles: cleaned,
      // attempted // uncomment for debug
    });
  } catch (err) {
    console.log("News API Error:", err?.response?.data || err.message || err);
    res.status(500).json("Failed to fetch news");
  }
});

// ============================================================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
