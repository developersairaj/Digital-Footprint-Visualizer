# 🔑 API Key Storage Guide

## 📍 Where to Save IntelligenceX API Key

You have **two options** for storing the API key:

---

## Option 1: Frontend (Current - localStorage) ⚠️

### Current Implementation:
The API key is stored in **browser localStorage** (client-side).

**Location in Code:**
- File: `index_simple.html`
- Function: `saveIntelxApiKey()`
- Storage: `localStorage.setItem('intelx_api_key', apiKey)`

### How It Works:
1. User enters API key in the website
2. Key is saved to browser's localStorage
3. Key persists across browser sessions
4. Key is accessible only to that browser/user

### ✅ Pros:
- Easy to set up
- No backend required
- User-specific (each user has their own key)
- Works immediately

### ❌ Cons:
- **Visible in browser DevTools** (security risk)
- **Not secure for production**
- Each user needs their own key
- Can be cleared if user clears browser data

### When to Use:
- ✅ Development/testing
- ✅ Personal projects
- ✅ When each user has their own IntelligenceX account

---

## Option 2: Backend (Recommended for Production) ✅

### Better Approach:
Store API key in **backend environment variables** (server-side).

### Implementation Steps:

#### Step 1: Create `.env` File

Create a file named `.env` in your project root:

```env
# IntelligenceX API Configuration
INTELX_API_KEY=your_api_key_here

# Optional: Other API keys
EMAILREP_API_KEY=optional_if_needed
HIBP_API_KEY=optional_if_needed
```

#### Step 2: Update Backend (`backend_simple.py`)

Add environment variable loading:

```python
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get IntelligenceX API key from environment
INTELX_API_KEY = os.getenv('INTELX_API_KEY', '')

# Add endpoint to handle breach checking
@app.post("/api/check-breaches")
async def check_breaches(request: BreachCheckRequest):
    """Check breaches using IntelligenceX API (backend proxy)"""
    query = request.query
    query_type = request.query_type  # 'email', 'phone', 'ip', 'domain'
    
    if not INTELX_API_KEY:
        raise HTTPException(status_code=500, detail="IntelligenceX API key not configured")
    
    try:
        # Step 1: Create search
        async with httpx.AsyncClient() as client:
            search_response = await client.post(
                'https://free.intelx.io/intelligent/search',
                headers={
                    'x-key': INTELX_API_KEY,
                    'Content-Type': 'application/json'
                },
                json={
                    'term': query,
                    'maxresults': 90,
                    'media': 0,
                    'target': {
                        'email': 1,
                        'phone': 2,
                        'ip': 3,
                        'domain': 4
                    }.get(query_type, 1),
                    'timeout': 1
                }
            )
            
            if search_response.status_code != 200:
                raise HTTPException(
                    status_code=search_response.status_code,
                    detail=f"IntelligenceX API error: {search_response.text}"
                )
            
            search_data = search_response.json()
            search_id = search_data.get('id')
            
            if not search_id:
                raise HTTPException(status_code=500, detail="No search ID returned")
            
            # Step 2: Wait and get results
            await asyncio.sleep(3)
            
            results_response = await client.get(
                f'https://free.intelx.io/intelligent/search/result?id={search_id}&limit=90',
                headers={'x-key': INTELX_API_KEY}
            )
            
            if results_response.status_code != 200:
                raise HTTPException(
                    status_code=results_response.status_code,
                    detail=f"Results API error: {results_response.text}"
                )
            
            return results_response.json()
            
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"API request failed: {str(e)}")
```

#### Step 3: Install python-dotenv

```bash
pip install python-dotenv
```

Or add to `requirements.txt`:
```
python-dotenv
```

#### Step 4: Update Frontend to Use Backend

Modify `index_simple.html` to call backend instead of direct API:

```javascript
async function checkBreachesIntelx(query, queryType = 'email') {
    const breachSection = document.getElementById('breachSection');
    const breachLoading = document.getElementById('breachLoading');
    const breachResults = document.getElementById('breachResults');
    
    breachSection.style.display = 'block';
    breachLoading.style.display = 'block';
    breachResults.innerHTML = '';

    try {
        // Call YOUR backend instead of IntelligenceX directly
        const response = await fetch('/api/check-breaches', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: query,
                query_type: queryType
            })
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        const resultsData = await response.json();
        breachLoading.style.display = 'none';
        renderIntelxResults(resultsData, query, queryType);
        
        return resultsData;
    } catch (error) {
        // Error handling...
    }
}
```

### ✅ Pros:
- **Secure** - API key never exposed to client
- **Centralized** - One key for all users
- **Better control** - Rate limiting, caching, logging
- **Production-ready** - Industry best practice

### ❌ Cons:
- Requires backend setup
- All users share same API key/quota
- More complex setup

### When to Use:
- ✅ Production deployments
- ✅ Public websites
- ✅ When you want centralized control
- ✅ When security is critical

---

## 🔒 Security Best Practices

### For Frontend Storage (localStorage):
1. ⚠️ **Not recommended for production**
2. Users can see key in DevTools
3. Each user needs their own IntelligenceX account
4. Key can be stolen if website is compromised

### For Backend Storage (.env):
1. ✅ **Add `.env` to `.gitignore`** (never commit API keys!)
2. ✅ Use environment variables in production
3. ✅ Rotate keys regularly
4. ✅ Monitor API usage
5. ✅ Use secrets management (AWS Secrets Manager, etc.) for production

---

## 📝 .gitignore Example

Make sure `.env` is in your `.gitignore`:

```gitignore
# Environment variables
.env
.env.local
.env.*.local

# API keys
*.key
secrets/
```

---

## 🚀 Quick Setup Summary

### For Development (Current):
- ✅ Use localStorage (already implemented)
- ✅ Each user enters their own key
- ✅ Works immediately

### For Production:
1. Create `.env` file with `INTELX_API_KEY=your_key`
2. Update backend to read from environment
3. Add backend endpoint `/api/check-breaches`
4. Update frontend to call backend
5. Add `.env` to `.gitignore`
6. Deploy backend with environment variables

---

## 💡 Recommendation

**For now (development):** Keep using localStorage - it's fine for testing.

**For production:** Move to backend storage with environment variables for security.

---

## 📚 Additional Resources

- **Environment Variables Guide**: https://12factor.net/config
- **Python dotenv**: https://pypi.org/project/python-dotenv/
- **FastAPI Environment**: https://fastapi.tiangolo.com/advanced/settings/
