from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import time
import uuid
from loguru import logger

from src.core.config import settings
from src.core.database import init_db
from src.core.security import SecurityHeaders
from src.api.routes import api_router
from src.core.exceptions import setup_exception_handlers
from src.connectors.registry import connector_registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Unified Workflow Connector API")
    await init_db()
    await connector_registry.initialize()
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Unified Workflow Connector API")


# PUBLIC_INTERFACE
def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        FastAPI: Configured FastAPI application instance
    """
    app = FastAPI(
        title="Unified Workflow Connector API",
        description="A unified connector platform for integrating various web tools like JIRA, Confluence, Slack, GitHub, and more.",
        version="1.0.0",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
        openapi_tags=[
            {
                "name": "health",
                "description": "Health check and system status endpoints"
            },
            {
                "name": "connectors",
                "description": "Connector management and operations"
            },
            {
                "name": "auth",
                "description": "Authentication and authorization"
            },
            {
                "name": "workflows",
                "description": "Workflow management and execution"
            },
            {
                "name": "webhooks",
                "description": "Webhook endpoints for external integrations"
            },
            {
                "name": "monitoring",
                "description": "Monitoring and analytics endpoints"
            },
            {
                "name": "websockets",
                "description": "Real-time WebSocket connections for live updates"
            }
        ]
    )

    # Security middleware
    app.add_middleware(SecurityHeaders)
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Process-Time"]
    )
    
    # Trusted host middleware
    if settings.ALLOWED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware, 
            allowed_hosts=settings.ALLOWED_HOSTS
        )

    # Request ID and timing middleware
    @app.middleware("http")
    async def add_request_id_and_timing(request: Request, call_next):
        """Add request ID and processing time to all requests"""
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Add request ID to request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Add headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        
        # Log request
        logger.info(
            "Request processed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "process_time": process_time,
                "status_code": response.status_code
            }
        )
        
        return response

    # Setup exception handlers
    setup_exception_handlers(app)

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()


# PUBLIC_INTERFACE
@app.get("/", tags=["health"])
def health_check():
    """
    Health check endpoint.
    
    Returns:
        dict: Health status and basic system information
    """
    return {
        "status": "healthy",
        "service": "Unified Workflow Connector API",
        "version": "1.0.0",
        "timestamp": time.time()
    }


# PUBLIC_INTERFACE
@app.get("/health", tags=["health"])
async def detailed_health_check():
    """
    Detailed health check with database and connector status.
    
    Returns:
        dict: Detailed health information including dependencies
    """
    health_data = {
        "status": "healthy",
        "service": "Unified Workflow Connector API",
        "version": "1.0.0",
        "timestamp": time.time(),
        "database": {"status": "unknown"},
        "connectors": {"status": "unknown", "count": 0}
    }
    
    try:
        # Check database connection
        from src.core.database import get_database
        db = await get_database()
        await db.command("ping")
        health_data["database"]["status"] = "healthy"
    except Exception as e:
        health_data["database"]["status"] = "unhealthy"
        health_data["database"]["error"] = str(e)
        health_data["status"] = "degraded"
    
    try:
        # Check connector registry
        connectors = await connector_registry.list_connectors()
        health_data["connectors"]["status"] = "healthy"
        health_data["connectors"]["count"] = len(connectors)
    except Exception as e:
        health_data["connectors"]["status"] = "unhealthy"
        health_data["connectors"]["error"] = str(e)
        health_data["status"] = "degraded"
    
    return health_data


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
