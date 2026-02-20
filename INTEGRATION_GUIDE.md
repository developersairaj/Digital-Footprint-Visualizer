# Frontend-Backend Integration Guide

## Overview

This guide explains how to connect the frontend HTML to the Python backend API.

## Backend API Base URL

When running locally:
```
http://localhost:8000
```

## Integration Steps

### 1. Update the `analyzeFootprint()` Function

Replace the existing `analyzeFootprint()` function in `index.html` with:

```javascript
window.analyzeFootprint = async function() {
    const input = document.getElementById('userInput').value.trim();

    if (!input) {
        alert('⚠️ Please enter an email or username to begin analysis');
        return;
    }

    const results = document.getElementById('results');
    results.style.display = 'block';
    setTimeout(() => {
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);

    try {
        const response = await fetch('http://localhost:8000/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identifier: input
            })
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();

        animateValue('platformCount', 0, data.platform_count, 2000);
        animateValue('exposureCount', 0, data.exposure_count, 2000);
        animateValue('threatLevel', 0, data.threat_level, 2000);

        animateRiskScore(data.risk_score);

        renderThreatMatrix(data.threats);
        renderTips(data.security_tips, data.action_items);

    } catch (error) {
        console.error('Error:', error);
        alert('❌ Failed to analyze footprint. Please try again.');
    }
};
```

### 2. Update `renderThreatMatrix()` Function

Modify to accept threat data from API:

```javascript
function renderThreatMatrix(threats = threatData) {
    const matrix = document.getElementById('threatMatrix');
    matrix.innerHTML = '';

    threats.forEach((threat, index) => {
        const item = document.createElement('div');
        item.className = 'threat-item';

        item.innerHTML = `
            <div class="threat-icon">${threat.icon}</div>
            <div class="threat-details">
                <div class="threat-name">${threat.name}</div>
                <div class="threat-bar">
                    <div class="threat-fill" style="width: 0%; background: ${threat.color};"></div>
                </div>
            </div>
            <div class="threat-percent" style="color: ${threat.color};">${threat.risk}%</div>
        `;

        matrix.appendChild(item);

        setTimeout(() => {
            item.querySelector('.threat-fill').style.width = threat.risk + '%';
        }, 100 * index);
    });
}
```

### 3. Update `renderTips()` Function

Modify to accept tips from API:

```javascript
function renderTips(apiSecurityTips = securityTips, apiActionItems = actionItems) {
    const securityList = document.getElementById('securityTips');
    const actionList = document.getElementById('actionItems');

    securityList.innerHTML = '';
    actionList.innerHTML = '';

    apiSecurityTips.forEach((tip, index) => {
        const li = document.createElement('li');
        li.className = 'tip-item';
        li.innerHTML = `<strong>${index + 1}.</strong> ${tip}`;
        securityList.appendChild(li);
    });

    apiActionItems.forEach((item, index) => {
        const li = document.createElement('li');
        li.className = 'tip-item';
        li.innerHTML = `<strong>${index + 1}.</strong> ${item}`;
        actionList.appendChild(li);
    });
}
```

### 4. Add Loading State (Optional)

Add a loading indicator while fetching:

```javascript
function showLoading() {
    const results = document.getElementById('results');
    results.innerHTML = `
        <div style="text-align: center; padding: 100px;">
            <div style="font-size: 4rem; margin-bottom: 20px;">⚡</div>
            <div style="font-size: 2rem; color: #00ffff;">Analyzing Digital Footprint...</div>
            <div style="color: #888; margin-top: 10px;">Scanning databases and networks</div>
        </div>
    `;
}
```

Call `showLoading()` at the start of `analyzeFootprint()`.

## Running Both Services

### Terminal 1 - Backend:
```bash
cd project
pip install -r requirements.txt
python backend.py
```

Backend will run on: `http://localhost:8000`

### Terminal 2 - Frontend:
```bash
cd project
python -m http.server 3000
```

Frontend will run on: `http://localhost:3000`

Or simply open `index.html` in your browser.

## API Testing

Test the backend API using curl:

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"identifier": "test@example.com"}'
```

## CORS Configuration

The backend is configured to allow all origins for development. For production:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
```

## Features Enabled by Backend

1. ✅ **Consistent Results**: Same identifier always returns same analysis
2. ✅ **Fast Response**: Lightweight stateless API
3. ✅ **Easy Deployment**: No database required
4. ✅ **Scalable**: Ready for production deployment
5. ✅ **Interactive Docs**: Built-in Swagger UI and ReDoc

## Next Steps

- Add user authentication
- Implement real threat detection algorithms
- Add email notifications for critical risks
- Create admin dashboard for analytics
- Add export to PDF functionality
- Implement scheduled re-scans
