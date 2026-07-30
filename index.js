// index.js
require('dotenv').config();          // loads .env locally (development only)

const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json()); // parse JSON bodies

const PORT = process.env.PORT || 3000; // Render will inject its own PORT

// ---------------------------
// Helper: call Genius Pay API
// ---------------------------
async function createGeniusPayPayment(data) {
  const url = 'https://geniuspay.ci/api/v1/merchant/payments';
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': process.env.GENIUS_PAY_API_KEY,        // you will set this on Render
      'X-API-Secret': process.env.GENIUS_PAY_API_SECRET, // **protected** on Render
    },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Genius Pay error ${response.status}: ${err}`);
  }

  return response.json(); // contains checkout_url, reference, etc.
}

// ---------------------------
// Public endpoint for your app
// ---------------------------
app.post('/payment', async (req, res) => {
  try {
    // Forward the request body directly (you may want validation in production)
    const geniusResponse = await createGeniusPayPayment(req.body);
    res.json(geniusResponse);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/', (req, res) => {
  res.send('W‑Com Genius Pay backend is running');
});

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
