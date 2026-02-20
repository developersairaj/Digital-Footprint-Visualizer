# 🔍 IntelligenceX API Setup Guide

## ✅ Perfect Solution for Comprehensive Breach Checking!

**IntelligenceX** is the ideal API for your website because it:
- ✅ **FREE tier available** - Just sign up, no payment required
- ✅ **Comprehensive scanning** - Email, Phone, IP, Domain, Username
- ✅ **90 results per query** - Free tier limit
- ✅ **Predictive analysis** - Shows where data appears
- ✅ **Multiple data sources** - Dark web, breaches, leaks, paste sites

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Create Free Account
1. Visit: **https://intelx.io/**
2. Click **"Sign Up"** (top right)
3. Fill in your details (email, password)
4. Verify your email address

### Step 2: Get Your FREE API Key
1. Log in to your IntelligenceX account
2. Click on **"Developer"** tab (in the top menu)
3. You'll see your **API Key** displayed
4. Copy the API key

### Step 3: Enter API Key in Website
1. Open your website (`index_simple.html`)
2. Find the **"IntelligenceX API Configuration"** section
3. Paste your API key
4. Click **"Save Key"**
5. Done! ✅

---

## 📊 What IntelligenceX Can Check

### ✅ Email Addresses
- Breach databases
- Leaked credentials
- Paste sites
- Dark web mentions

### ✅ Phone Numbers
- Data breaches
- Leaked databases
- Public records
- Spam lists

### ✅ IP Addresses
- Breach records
- Attack logs
- Geolocation data
- Threat intelligence

### ✅ Domains
- Subdomain enumeration
- Certificate transparency
- DNS records
- Historical data

### ✅ Usernames
- Account discovery
- Platform presence
- Leaked credentials

---

## 🔑 API Endpoints Used

### Free Tier Endpoint:
```
https://free.intelx.io/intelligent/search
```

### Features:
- **90 results per query** (free tier)
- **Multiple selector types** (email, phone, IP, domain)
- **Comprehensive data sources**
- **No rate limits** (within reason)

---

## 📝 API Request Format

```javascript
// Step 1: Create Search
POST https://free.intelx.io/intelligent/search
Headers:
  x-key: YOUR_API_KEY
  Content-Type: application/json
Body:
{
  "term": "email@example.com",
  "maxresults": 90,
  "media": 0,
  "target": 1,  // 1=email, 2=phone, 3=IP, 4=domain
  "timeout": 1
}

// Step 2: Get Results
GET https://free.intelx.io/intelligent/search/result?id=SEARCH_ID&limit=90
Headers:
  x-key: YOUR_API_KEY
```

---

## 🎯 Target Types

| Type | Value | Description |
|------|-------|-------------|
| Email | `1` | Email address search |
| Phone | `2` | Phone number search |
| IP | `3` | IP address search |
| Domain | `4` | Domain name search |

---

## 💡 Usage Tips

1. **Wait for Processing**: After creating a search, wait 2-3 seconds before fetching results
2. **Respect Limits**: Free tier allows 90 results per query
3. **Cache Results**: Store results to reduce API calls
4. **Error Handling**: Always handle API errors gracefully
5. **Privacy**: Never log sensitive user data

---

## 🔒 Security Best Practices

1. **Store API Key Securely**: Use localStorage (client-side) or environment variables (server-side)
2. **Validate Input**: Always validate user input before API calls
3. **Rate Limiting**: Implement client-side rate limiting
4. **Error Messages**: Don't expose API keys in error messages
5. **HTTPS Only**: Always use HTTPS for API calls

---

## 📚 Additional Resources

- **IntelligenceX Website**: https://intelx.io/
- **API Documentation**: https://help.intelx.io/docs/api/
- **Search API Docs**: https://help.intelx.io/api/search/
- **Developer Portal**: Login → Developer Tab

---

## 🆚 Comparison with Other APIs

| Feature | IntelligenceX | EmailRep | HIBP |
|---------|-------------|----------|------|
| **Cost** | Free (signup) | Free | Free |
| **Email** | ✅ | ✅ | ✅ |
| **Phone** | ✅ | ❌ | ❌ |
| **IP** | ✅ | ❌ | ❌ |
| **Domain** | ✅ | ❌ | ❌ |
| **Password** | ❌ | ❌ | ✅ |
| **Results/Query** | 90 | 1 | Unlimited |
| **API Key** | Required (free) | Not required | Optional |

**Winner**: IntelligenceX for comprehensive scanning! 🏆

---

## 🎉 Ready to Use!

Once you've added your API key, your website can:
- ✅ Check email breaches
- ✅ Check phone number breaches  
- ✅ Check IP address breaches
- ✅ Check domain breaches
- ✅ Show comprehensive breach data
- ✅ Display predictive results

**No subscription needed - completely free!** 🆓
