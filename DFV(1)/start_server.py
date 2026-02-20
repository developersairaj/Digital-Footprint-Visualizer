#!/usr/bin/env python3
"""
Simple script to start the NEXUS backend server
"""
import uvicorn
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("🚀 Starting NEXUS Backend Server...")
    print("📍 Server will run on: http://localhost:8000")
    print("🌐 Open your browser to: http://localhost:8000")
    print("⏹️  Press Ctrl+C to stop the server")
    print()
    
    try:
        uvicorn.run(
            "backend_simple:app",
            host="localhost",
            port=8000,
            reload=False,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n✅ Server stopped gracefully")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)
