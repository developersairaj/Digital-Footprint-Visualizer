# Digital Footprint Visualizer - Setup Guide

## 🔒 Real-Time Breach Data Integration

This application uses the **Have I Been Pwned (HIBP)** API to check for data breaches in real-time.

### 📋 API Overview

**Have I Been Pwned (HIBP)** is the best choice for breach checking because:
- ✅ **Free tier available** (with rate limits)
- ✅ **Trusted and widely used** (created by security expert Troy Hunt)
- ✅ **Comprehensive database** (billions of breached accounts)
- ✅ **Multiple endpoints** for emails, passwords, and usernames
- ✅ **Well-documented API**

### 🔑 API Key Setup (Optional but Recommended)

1. **Get Your Free API Key:**
   - Visit: https://haveibeenpwned.com/API/Key
   - Sign up for a free account
   - Copy your API key

2. **Enter API Key:**
   - Click on the API Configuration section on the website
   - Paste your API key
   - Click "Save Key"
   - The key is stored locally in your browser

**Benefits of using an API key:**
- Higher rate limits (1500 requests/day vs 150 without key)
- Better reliability
- No rate limit errors

### 🌐 CORS Limitations & Solutions

**Problem:** HIBP API doesn't support browser CORS directly.

**Current Solution (Development):**
- Using a public CORS proxy (`api.allorigins.win`)
- Works for testing but not recommended for production

**Production Solution (Recommended):**
Set up a backend proxy server to handle API calls securely.

#### Option 1: Node.js Backend Proxy

```javascript
// server.js (Express.js example)
const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

app.post('/api/check-breaches', async (req, res) => {
    const { email, apiKey } = req.body;
    
    try {
        const headers = {
            'User-Agent': 'Digital-Footprint-Visualizer',
            'hibp-api-key': apiKey || ''
        };
        
        const response = await fetch(
            `https://haveibeenpwned.com/api/v3/breachedaccount/${email}?truncateResponse=false`,
            { headers }
        );
        
        if (response.status === 404) {
            return res.json([]);
        }
        
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(3000, () => console.log('Proxy server running on port 3000'));
```

#### Option 2: Python Flask Backend Proxy

```python
# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

@app.route('/api/check-breaches', methods=['POST'])
def check_breaches():
    email = request.json.get('email')
    api_key = request.json.get('apiKey', '')
    
    headers = {
        'User-Agent': 'Digital-Footprint-Visualizer',
        'hibp-api-key': api_key
    }
    
    url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false'
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return jsonify([])
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=3000)
```

### 🔐 Password Checking

The password checking feature uses HIBP's **Range API** which:
- ✅ **Supports CORS** (works directly from browser)
- ✅ **Privacy-preserving** (only sends first 5 chars of hash)
- ✅ **No API key required** (but recommended for rate limits)

**How it works:**
1. Password is hashed using SHA-1
2. First 5 characters of hash are sent to API
3. API returns all hashes with that prefix
4. Browser checks if full hash matches locally
5. Password never leaves your browser in plain text

### 📊 API Endpoints Used

1. **Breached Account API** (`/api/v3/breachedaccount/{account}`)
   - Checks if email/username was breached
   - Returns breach details
   - Requires API key for higher limits

2. **Range API** (`/api/range/{hashPrefix}`)
   - Checks password breaches
   - Supports CORS
   - No API key required (but recommended)

### 🚀 Deployment Recommendations

1. **Backend Proxy:** Always use a backend proxy in production
2. **API Key:** Store API key securely on backend, not in frontend
3. **Rate Limiting:** Implement rate limiting on your backend
4. **Error Handling:** Handle API errors gracefully
5. **Caching:** Cache results to reduce API calls

### 📝 Environment Variables (Backend)

```env
HIBP_API_KEY=your_api_key_here
PROXY_PORT=3000
```

### 🔒 Security Best Practices

1. **Never expose API keys** in frontend code
2. **Use HTTPS** for all API calls
3. **Validate input** before sending to API
4. **Implement rate limiting** to prevent abuse
5. **Log API usage** for monitoring

### 📚 Additional Resources

- **HIBP API Documentation:** https://haveibeenpwned.com/API/v3
- **API Key Registration:** https://haveibeenpwned.com/API/Key
- **Rate Limits:** https://haveibeenpwned.com/API/v3#RateLimiting
- **Privacy Policy:** https://haveibeenpwned.com/Privacy

### 🆘 Troubleshooting

**Issue: CORS Error**
- Solution: Use backend proxy or CORS proxy

**Issue: Rate Limit Exceeded**
- Solution: Get API key for higher limits

**Issue: API Key Not Working**
- Solution: Verify key is correct and active

**Issue: No Breaches Found**
- Solution: This is normal if email hasn't been breached

---

**Note:** This setup guide provides the foundation for integrating real-time breach data. For production deployments, always use a secure backend proxy to protect API keys and handle CORS properly.
