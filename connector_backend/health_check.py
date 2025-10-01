#!/usr/bin/env python3
"""
Health check script for the Unified Workflow Connector API.

This script can be used by monitoring systems, Docker healthchecks,
or load balancers to verify the application is running properly.
"""

import sys
import asyncio
import httpx
import os
from datetime import datetime

async def check_health(base_url: str = None, timeout: int = 30) -> bool:
    """
    Perform health check on the API.
    
    Args:
        base_url: Base URL of the API
        timeout: Request timeout in seconds
        
    Returns:
        bool: True if healthy, False otherwise
    """
    if not base_url:
        host = os.getenv("HOST", "localhost")
        port = os.getenv("PORT", "8000")
        base_url = f"http://{host}:{port}"
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Check basic health endpoint
            response = await client.get(f"{base_url}/health")
            
            if response.status_code != 200:
                print(f"❌ Health check failed: HTTP {response.status_code}")
                return False
            
            health_data = response.json()
            
            # Check overall status
            if health_data.get("status") not in ["healthy", "degraded"]:
                print(f"❌ System status: {health_data.get('status')}")
                return False
            
            # Check database status
            db_status = health_data.get("database", {}).get("status")
            if db_status != "healthy":
                print(f"⚠️  Database status: {db_status}")
                if health_data.get("status") == "unhealthy":
                    return False
            
            # Check connectors status
            connectors_status = health_data.get("connectors", {}).get("status")
            if connectors_status != "healthy":
                print(f"⚠️  Connectors status: {connectors_status}")
            
            print(f"✅ System is {health_data.get('status')}")
            print(f"📊 Database: {db_status}")
            print(f"🔌 Connectors: {connectors_status} ({health_data.get('connectors', {}).get('count', 0)} registered)")
            
            return True
            
    except httpx.TimeoutException:
        print(f"❌ Health check timeout after {timeout}s")
        return False
    except httpx.RequestError as e:
        print(f"❌ Health check request failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

async def check_endpoints(base_url: str = None) -> bool:
    """
    Check critical API endpoints.
    
    Args:
        base_url: Base URL of the API
        
    Returns:
        bool: True if all endpoints are accessible
    """
    if not base_url:
        host = os.getenv("HOST", "localhost")
        port = os.getenv("PORT", "8000")
        base_url = f"http://{host}:{port}"
    
    endpoints = [
        "/",
        "/docs",
        "/openapi.json",
        "/api/v1/connectors/"
    ]
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for endpoint in endpoints:
                try:
                    response = await client.get(f"{base_url}{endpoint}")
                    if response.status_code >= 500:
                        print(f"❌ Endpoint {endpoint}: HTTP {response.status_code}")
                        return False
                    else:
                        print(f"✅ Endpoint {endpoint}: HTTP {response.status_code}")
                except Exception as e:
                    print(f"❌ Endpoint {endpoint}: {e}")
                    return False
            
            return True
            
    except Exception as e:
        print(f"❌ Endpoint check failed: {e}")
        return False

def main():
    """Main health check function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Health check for Unified Workflow Connector API")
    parser.add_argument("--url", help="Base URL of the API", default=None)
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds", default=30)
    parser.add_argument("--endpoints", action="store_true", help="Check critical endpoints")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    print(f"🔍 Health check started at {datetime.now().isoformat()}")
    
    async def run_checks():
        """Run all health checks."""
        # Basic health check
        health_ok = await check_health(args.url, args.timeout)
        
        # Endpoint checks if requested
        endpoints_ok = True
        if args.endpoints:
            endpoints_ok = await check_endpoints(args.url)
        
        return health_ok and endpoints_ok
    
    try:
        # Run the health checks
        all_ok = asyncio.run(run_checks())
        
        if all_ok:
            print("✅ All health checks passed")
            sys.exit(0)
        else:
            print("❌ Health checks failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Health check interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Health check error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
