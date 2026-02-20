# 🆓 Free Breach Checking APIs - No Subscription Required!

## ✅ Current Implementation: EmailRep API

Your website now uses **EmailRep API** - completely free with no API key required!

### EmailRep API Features:
- ✅ **100% Free** - No API key needed
- ✅ **Free Tier:** 10 queries/day, 250 queries/month
- ✅ **Supports CORS** - Works directly from browser
- ✅ **Comprehensive Data:**
  - Credentials exposed status
  - Email reputation score
  - Suspicious activity detection
  - Malicious activity reports
  - Domain reputation
  - Social media presence
  - Last seen information

### How It Works:
```javascript
// Simple API call - no authentication needed!
fetch(`https://emailrep.io/${email}`)
  .then(response => response.json())
  .then(data => {
    // Check if credentials exposed
    if (data.credentials_exposed) {
      // Show breach warning
    }
  });
```

### API Response Example:
```json
{
  "email": "test@example.com",
  "reputation": "low",
  "suspicious": true,
  "references": 5,
  "details": [
    "Domain is suspicious",
    "Email found in breach databases"
  ],
  "credentials_exposed": true,
  "malicious_activity": [
    "Phishing campaigns",
    "Spam reports"
  ],
  "last_seen": "2024-01-15"
}
```

---

## 🔐 Password Checking: HIBP Range API

For password checking, we use **HIBP Range API** which is also completely free!

### Features:
- ✅ **Free** - No API key required
- ✅ **Privacy-preserving** - Uses k-anonymity
- ✅ **Supports CORS** - Works from browser
- ✅ **No rate limits** for range API

### How It Works:
1. Password is hashed with SHA-1
2. First 5 characters sent to API
3. API returns all matching hashes
4. Browser checks locally (password never sent in full)

---

## 🆚 Comparison: EmailRep vs HIBP

| Feature | EmailRep | HIBP |
|---------|----------|------|
| **Cost** | Free (10/day) | Free (150/day) |
| **API Key** | Not required | Optional (free) |
| **CORS Support** | ✅ Yes | ❌ No (needs proxy) |
| **Breach Data** | ✅ Yes | ✅ Yes |
| **Password Check** | ❌ No | ✅ Yes |
| **Reputation Score** | ✅ Yes | ❌ No |
| **Malicious Activity** | ✅ Yes | ❌ No |

**Winner:** EmailRep for email checking (easier, no proxy needed), HIBP for password checking

---

## 🚀 Alternative Free APIs (If Needed)

### 1. BreachDirectory API
- **URL:** `https://breachdirectory.com/api/v1/breaches`
- **Free Tier:** Limited free access
- **Requires:** May need API key for some endpoints
- **Best For:** Additional breach data sources

### 2. LeakCheck API
- **URL:** Various endpoints
- **Free Tier:** Limited
- **Requires:** Registration may be needed
- **Best For:** Alternative breach checking

### 3. DeHashed API
- **URL:** `https://dehashed.com/api`
- **Free Tier:** ❌ Paid only
- **Requires:** Subscription
- **Best For:** Not suitable (requires payment)

---

## 💡 Why EmailRep is Perfect for Your Site

1. **Zero Setup** - Works immediately, no configuration
2. **No API Keys** - No need to manage keys or subscriptions
3. **CORS Support** - Works directly from browser
4. **Comprehensive** - Provides reputation + breach data
5. **Free Forever** - Community tier is always free
6. **Easy Integration** - Simple REST API

---

## 📊 Rate Limits

### EmailRep Free Tier:
- **Daily Limit:** 10 queries/day
- **Monthly Limit:** 250 queries/month
- **Upgrade:** $20/month for 10,000 queries/month

### HIBP Range API:
- **No Rate Limit** - Public endpoint
- **Free Forever** - No limits

---

## 🎯 Recommendations

### For Your Website:
✅ **Use EmailRep** for email breach checking
- No API key needed
- Works from browser
- Provides comprehensive data

✅ **Use HIBP Range API** for password checking
- Free and unlimited
- Privacy-preserving
- Works from browser

### If You Need More:
- Consider EmailRep paid tier ($20/month) for higher limits
- Or implement backend caching to reduce API calls
- Or use multiple free APIs in rotation

---

## 🔒 Security Best Practices

1. **Rate Limiting:** Implement client-side rate limiting
2. **Caching:** Cache results to reduce API calls
3. **Error Handling:** Handle API errors gracefully
4. **Privacy:** Never log sensitive data
5. **Validation:** Validate email format before API calls

---

## 📚 Resources

- **EmailRep API:** https://emailrep.io/
- **EmailRep Docs:** https://emailrep.io/docs
- **HIBP Range API:** https://haveibeenpwned.com/API/v3#PwnedPasswords
- **EmailRep GitHub:** https://github.com/sublimesecurity/emailrep

---

**No subscriptions, no API keys, no hassle - just free breach checking!** 🎉
