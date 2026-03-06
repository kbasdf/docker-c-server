const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({
  origin: ["http://localhost:3000","http://localhost:5000","http://localhost:4000","http://localhost:5050"],
  methods: ["POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
   credentials: true
}));

// ✅ Add JSON body parsing
app.use(express.json());

const SECRET_KEY = "hula-shula-bula-kula";

// Endpoint to generate token
app.post('/api/token', (req, res) => {
  const { email } = req.body;
  console.log("Token request for:", email);

  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  try {
    const payload = { email };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '15m' });
    res.json({ success: true, token });
  } catch (err) {
    console.error("JWT error:", err);
    res.status(500).json({ success: false, message: "Token generation failed" });
  }
});

app.listen(6060, () => {
  console.log("Token service running on http://localhost:6060");
});