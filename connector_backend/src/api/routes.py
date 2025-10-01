from fastapi import APIRouter

from src.api.endpoints import connectors, auth, workflows, webhooks, monitoring, websockets

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(
    connectors.router,
    prefix="/connectors",
    tags=["connectors"]
)

api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["auth"]
)

api_router.include_router(
    workflows.router,
    prefix="/workflows",
    tags=["workflows"]
)

api_router.include_router(
    webhooks.router,
    prefix="/webhooks",
    tags=["webhooks"]
)

api_router.include_router(
    monitoring.router,
    prefix="/monitoring",
    tags=["monitoring"]
)

api_router.include_router(
    websockets.router,
    prefix="/ws",
    tags=["websockets"]
)
