# Quick Start Guide

Get the Digital Footprint Visualizer backend running in 3 steps.

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Run the Backend

```bash
python backend.py
```

The API will start on `http://localhost:8000`

## Step 3: Test the API

### Option A: Use the test script
```bash
python test_backend.py
```

### Option B: Manual test with curl
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"identifier": "test@example.com"}'
```

### Option C: Interactive API docs
Open your browser to: `http://localhost:8000/docs`

## Verify Everything Works

You should see:
- ✅ Backend running on port 8000
- ✅ Health check returns "healthy"
- ✅ Analysis endpoint returns risk data
- ✅ All 6 tests pass when running test_backend.py

## Common Issues

**Port already in use:**
```bash
# Change the port in backend.py or kill the process
lsof -ti:8000 | xargs kill
```

**Import errors:**
```bash
# Make sure you're in the project directory
cd project
pip install -r requirements.txt --upgrade
```

## Next Steps

- Read `INTEGRATION_GUIDE.md` to connect the frontend
- Review `README_BACKEND.md` for full API documentation
- Check `backend.py` for customization options
