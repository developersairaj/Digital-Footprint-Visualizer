# NEXUS : FOCUS ZONE TEAM IN ASSOCIATES PRESENTS
## 🔐 Digital Footprint Visualizer Code Written & Directed By Tech Builders Team

Digital Footprint Visualizer is a Digital Intelligence Platform that analyzes a user’s online presence using an email address or phone number to detect possible data breaches, leaks, and exposure risks.

It provides a clean dashboard interface with a calculated risk score based on multiple exposure factors.

---

# 🚀 Features

- Email / Phone based digital footprint analysis
- Breach detection
- Risk score calculation
- Cyber-style modern dashboard UI
- FastAPI backend
- Simple HTML frontend
- API-based architecture

---

# 📁 Project Structure

```
DFV(1)/
│
├── index2.html                # Frontend UI
├── simple_backend.py          # FastAPI backend
├── start_server.py            # Server starter
├── dfv_audit/                 # Core scanning & risk logic
│   ├── backend/
│   │   ├── app.py
│   │   ├── scanner.py
│   │   ├── risk.py
│
├── requirements_simple.txt    # Dependencies
└── README.md
```

---

# ⚙️ Requirements

- Python 3.8 or higher
- pip

Install dependencies:

```
pip install -r requirements_simple.txt
```

---

# ▶️ How to Run the Project

## Step 1 — Start Backend Server

```
python simple_backend.py
```

Server will start at:

```
http://localhost:8000
```

---

## Step 2 — Open Frontend

Open:

```
index2.html
```

in your browser.

You can double-click the file or right-click → Open with browser.

---

# 🔎 How It Works

1. User enters email or phone number.
2. Frontend sends POST request to:
   ```
   /api/analyze
   ```
3. Backend scans for:
   - Data breaches
   - Exposure sources
   - Public data traces
   - Risk indicators
4. Risk score is calculated.
5. Dashboard displays analysis results.

---

# 📊 Risk Score Calculation

```
Risk Score = Sum of All Risk Factors / Total Number of Factors
```

Example factors:
- Breach count
- Data leak exposure
- Dark web presence
- Public exposure
- Account reuse
- Metadata traces

---

# 📡 API Endpoint

### POST /api/analyze

Request Body:

```json
{
  "email": "example@gmail.com"
}
```

Response Example:

```json
{
  "risk_score": 0.42,
  "breaches": 1,
  "exposures": [
    "Public data exposure",
    "Possible credential leak"
  ]
}
```

---

# 🧪 Run with Auto Reload (Development Mode)

```
uvicorn simple_backend:app --reload
```

---

# 🛠 Tech Stack

- Python
- FastAPI
- Uvicorn
- HTML5
- CSS
- JavaScript

---

# 🎯 Purpose

This project demonstrates:
- Digital intelligence analysis
- API-based architecture
- Risk modeling logic
- Cybersecurity awareness tools

---

# 👨‍💻 Author

Sairaj Khanvilkar  
GitHub: https://github.com/developersairaj

---

# 📌 License

This project is for educational and research purposes.
