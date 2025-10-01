#!/usr/bin/env python3
"""
Startup script for the Unified Workflow Connector API.

This script provides a convenient way to start the FastAPI application
with proper configuration and error handling.
"""

import sys
import os
import uvicorn
from pathlib import Path

# Add the src directory to the Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

def check_environment():
    """Check if required environment variables are set."""
    required_vars = [
        "SECRET_KEY",
        "ENCRYPTION_KEY", 
        "MONGODB_URL"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables in your .env file or environment.")
        print("See .env.example for reference.")
        return False
    
    return True

def main():
    """Main startup function."""
    print("🚀 Starting Unified Workflow Connector API...")
    
    # Check environment variables
    if not check_environment():
        sys.exit(1)
    
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("DEBUG", "false").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    workers = int(os.getenv("WORKERS", "1"))
    
    print(f"📡 Host: {host}")
    print(f"🔌 Port: {port}")
    print(f"🔄 Reload: {reload}")
    print(f"📝 Log Level: {log_level}")
    print(f"👥 Workers: {workers}")
    
    try:
        if reload or workers == 1:
            # Development mode or single worker
            uvicorn.run(
                "main:app",
                host=host,
                port=port,
                reload=reload,
                log_level=log_level,
                access_log=True,
                loop="uvloop"
            )
        else:
            # Production mode with multiple workers
            uvicorn.run(
                "main:app",
                host=host,
                port=port,
                workers=workers,
                log_level=log_level,
                access_log=True,
                loop="uvloop"
            )
    except KeyboardInterrupt:
        print("\n🛑 Shutting down gracefully...")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
