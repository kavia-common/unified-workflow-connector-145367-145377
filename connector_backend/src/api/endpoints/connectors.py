from fastapi import APIRouter, HTTPException, status, Depends, Query, Request
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.models.schemas import (
    ConnectorResponse, ConnectorCreate, ConnectorUpdate,
    OAuthLoginRequest, OAuthLoginResponse,
    SearchResponse, StatusResponse
)
from src.core.database import get_database
from src.core.security import get_current_user, create_state_token, verify_state_token, encryption_manager
from src.core.exceptions import (
    ConnectorNotFoundException, ValidationException, 
    TokenExpiredException
)
from src.connectors.registry import connector_registry
from src.connectors.base import BaseConnector
from loguru import logger

router = APIRouter()


# PUBLIC_INTERFACE
@router.get("/", response_model=List[Dict[str, Any]], summary="List available connectors")
async def list_available_connectors():
    """
    Get list of all available connectors with their metadata.
    
    Returns:
        List[dict]: Available connectors with metadata
    """
    try:
        connectors = await connector_registry.list_connectors()
        return connectors
    except Exception as e:
        logger.error(f"Failed to list connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve connector list"
        )


# PUBLIC_INTERFACE
@router.get("/tenant", response_model=List[ConnectorResponse], summary="List tenant connectors")
async def list_tenant_connectors(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get list of connectors configured for the current tenant.
    
    Args:
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        List[ConnectorResponse]: Tenant's configured connectors
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        cursor = db.connectors.find({"tenant_id": tenant_id, "is_active": True})
        connectors = []
        
        async for doc in cursor:
            # Remove sensitive data
            if doc.get("credentials"):
                doc["credentials"] = None
            
            connectors.append(ConnectorResponse(
                id=str(doc["_id"]),
                tenant_id=doc["tenant_id"],
                connector_id=doc["connector_id"],
                connector_type=doc["connector_type"],
                status=doc["status"],
                auth_type=doc["auth_type"],
                metadata=doc["metadata"],
                last_sync_at=doc.get("last_sync_at"),
                last_error=doc.get("last_error"),
                is_active=doc["is_active"],
                created_at=doc["created_at"],
                updated_at=doc.get("updated_at")
            ))
        
        return connectors
        
    except Exception as e:
        logger.error(f"Failed to list tenant connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tenant connectors"
        )


# PUBLIC_INTERFACE
@router.post("/", response_model=ConnectorResponse, summary="Create connector")
async def create_connector(
    connector_data: ConnectorCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Create a new connector for the tenant.
    
    Args:
        connector_data: Connector creation data
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        ConnectorResponse: Created connector
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    # Validate connector exists in registry
    if not connector_registry.is_registered(connector_data.connector_id):
        raise ConnectorNotFoundException(connector_data.connector_id)
    
    # Check if connector already exists for tenant
    existing = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_data.connector_id
    })
    
    if existing:
        raise ValidationException(f"Connector '{connector_data.connector_id}' already exists for tenant")
    
    try:
        # Create connector document
        connector_doc = {
            "tenant_id": tenant_id,
            "connector_id": connector_data.connector_id,
            "connector_type": connector_data.connector_type,
            "status": "disconnected",
            "auth_type": connector_data.auth_type,
            "config": connector_data.config.model_dump(),
            "credentials": None,
            "metadata": connector_data.metadata.model_dump(),
            "last_sync_at": None,
            "last_error": None,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": None
        }
        
        result = await db.connectors.insert_one(connector_doc)
        
        # Retrieve created connector
        created_connector = await db.connectors.find_one({"_id": result.inserted_id})
        
        return ConnectorResponse(
            id=str(created_connector["_id"]),
            tenant_id=created_connector["tenant_id"],
            connector_id=created_connector["connector_id"],
            connector_type=created_connector["connector_type"],
            status=created_connector["status"],
            auth_type=created_connector["auth_type"],
            metadata=created_connector["metadata"],
            last_sync_at=created_connector.get("last_sync_at"),
            last_error=created_connector.get("last_error"),
            is_active=created_connector["is_active"],
            created_at=created_connector["created_at"],
            updated_at=created_connector.get("updated_at")
        )
        
    except Exception as e:
        logger.error(f"Failed to create connector: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create connector"
        )


# PUBLIC_INTERFACE
@router.get("/{connector_id}", response_model=ConnectorResponse, summary="Get connector")
async def get_connector(
    connector_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get a specific connector by ID.
    
    Args:
        connector_id: Connector identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        ConnectorResponse: Connector details
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    connector = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector:
        raise ConnectorNotFoundException(connector_id)
    
    # Remove sensitive data
    if connector.get("credentials"):
        connector["credentials"] = None
    
    return ConnectorResponse(
        id=str(connector["_id"]),
        tenant_id=connector["tenant_id"],
        connector_id=connector["connector_id"],
        connector_type=connector["connector_type"],
        status=connector["status"],
        auth_type=connector["auth_type"],
        metadata=connector["metadata"],
        last_sync_at=connector.get("last_sync_at"),
        last_error=connector.get("last_error"),
        is_active=connector["is_active"],
        created_at=connector["created_at"],
        updated_at=connector.get("updated_at")
    )


# PUBLIC_INTERFACE
@router.put("/{connector_id}", response_model=ConnectorResponse, summary="Update connector")
async def update_connector(
    connector_id: str,
    update_data: ConnectorUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Update a connector configuration.
    
    Args:
        connector_id: Connector identifier
        update_data: Update data
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        ConnectorResponse: Updated connector
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    # Check connector exists
    connector = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector:
        raise ConnectorNotFoundException(connector_id)
    
    try:
        # Build update document
        update_doc = {"updated_at": datetime.utcnow()}
        
        if update_data.status is not None:
            update_doc["status"] = update_data.status
        if update_data.config is not None:
            update_doc["config"] = update_data.config.model_dump()
        if update_data.metadata is not None:
            update_doc["metadata"] = update_data.metadata.model_dump()
        if update_data.is_active is not None:
            update_doc["is_active"] = update_data.is_active
        
        # Update connector
        await db.connectors.update_one(
            {"tenant_id": tenant_id, "connector_id": connector_id},
            {"$set": update_doc}
        )
        
        # Retrieve updated connector
        updated_connector = await db.connectors.find_one({
            "tenant_id": tenant_id,
            "connector_id": connector_id
        })
        
        return ConnectorResponse(
            id=str(updated_connector["_id"]),
            tenant_id=updated_connector["tenant_id"],
            connector_id=updated_connector["connector_id"],
            connector_type=updated_connector["connector_type"],
            status=updated_connector["status"],
            auth_type=updated_connector["auth_type"],
            metadata=updated_connector["metadata"],
            last_sync_at=updated_connector.get("last_sync_at"),
            last_error=updated_connector.get("last_error"),
            is_active=updated_connector["is_active"],
            created_at=updated_connector["created_at"],
            updated_at=updated_connector.get("updated_at")
        )
        
    except Exception as e:
        logger.error(f"Failed to update connector: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update connector"
        )


# PUBLIC_INTERFACE
@router.delete("/{connector_id}", response_model=StatusResponse, summary="Delete connector")
async def delete_connector(
    connector_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Delete a connector and revoke its credentials.
    
    Args:
        connector_id: Connector identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Deletion status
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    # Check connector exists
    connector = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector:
        raise ConnectorNotFoundException(connector_id)
    
    try:
        # TODO: Revoke tokens with external service if possible
        
        # Delete connector
        await db.connectors.delete_one({
            "tenant_id": tenant_id,
            "connector_id": connector_id
        })
        
        return StatusResponse(
            status="success",
            message=f"Connector '{connector_id}' deleted successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to delete connector: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete connector"
        )


# OAuth Endpoints

# PUBLIC_INTERFACE
@router.post("/{connector_id}/oauth/login", response_model=OAuthLoginResponse, summary="Start OAuth flow")
async def oauth_login(
    connector_id: str,
    request: Request,
    login_request: OAuthLoginRequest = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Start OAuth authorization flow for a connector.
    
    Args:
        connector_id: Connector identifier
        request: FastAPI request object
        login_request: OAuth login request data
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        OAuthLoginResponse: Authorization URL and state
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    # Check connector exists
    connector_doc = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector_doc:
        raise ConnectorNotFoundException(connector_id)
    
    try:
        # Get connector instance
        connector = connector_registry.create_connector(
            connector_id, 
            connector_doc["config"]
        )
        
        # Create state token
        state = create_state_token(tenant_id, connector_id)
        
        # Build redirect URI
        base_url = str(request.base_url).rstrip('/')
        redirect_uri = f"{base_url}/api/v1/connectors/{connector_id}/oauth/callback"
        
        # Get authorization URL
        auth_url = await connector.get_oauth_authorize_url(
            tenant_id=tenant_id,
            state=state,
            redirect_uri=redirect_uri
        )
        
        return OAuthLoginResponse(
            authorization_url=auth_url,
            state=state
        )
        
    except Exception as e:
        logger.error(f"Failed to start OAuth flow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start OAuth flow"
        )


# PUBLIC_INTERFACE
@router.get("/{connector_id}/oauth/callback", summary="OAuth callback")
async def oauth_callback(
    connector_id: str,
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    db = Depends(get_database)
):
    """
    Handle OAuth callback and exchange code for tokens.
    
    Args:
        connector_id: Connector identifier
        request: FastAPI request object
        code: OAuth authorization code
        state: OAuth state parameter
        error: OAuth error code
        error_description: OAuth error description
        db: Database connection
        
    Returns:
        dict: Success status and redirect information
    """
    # Handle OAuth errors
    if error:
        logger.error(f"OAuth error for {connector_id}: {error} - {error_description}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {error_description or error}"
        )
    
    try:
        # Verify state token
        state_data = verify_state_token(state)
        tenant_id = state_data.get("tenant_id")
        
        if state_data.get("connector_id") != connector_id:
            raise ValidationException("State token connector mismatch")
        
        # Get connector document
        connector_doc = await db.connectors.find_one({
            "tenant_id": tenant_id,
            "connector_id": connector_id
        })
        
        if not connector_doc:
            raise ConnectorNotFoundException(connector_id)
        
        # Get connector instance
        connector = connector_registry.create_connector(
            connector_id,
            connector_doc["config"]
        )
        
        # Build redirect URI
        base_url = str(request.base_url).rstrip('/')
        redirect_uri = f"{base_url}/api/v1/connectors/{connector_id}/oauth/callback"
        
        # Exchange code for tokens
        token_data = await connector.exchange_code_for_tokens(
            tenant_id=tenant_id,
            code=code,
            state=state,
            redirect_uri=redirect_uri
        )
        
        # Encrypt and store credentials
        credentials = {
            "access_token": encryption_manager.encrypt(token_data["access_token"]),
            "refresh_token": encryption_manager.encrypt(token_data.get("refresh_token", "")),
            "token_expires_at": datetime.utcnow().timestamp() + token_data.get("expires_in", 3600),
            "resources": token_data.get("resources", [])
        }
        
        # Update connector with credentials and status
        await db.connectors.update_one(
            {"tenant_id": tenant_id, "connector_id": connector_id},
            {
                "$set": {
                    "credentials": credentials,
                    "status": "connected",
                    "last_sync_at": datetime.utcnow(),
                    "last_error": None,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return {
            "status": "success",
            "message": f"Successfully connected {connector_id}",
            "connector_id": connector_id
        }
        
    except Exception as e:
        logger.error(f"OAuth callback failed for {connector_id}: {e}")
        
        # Update connector with error status
        try:
            if 'tenant_id' in locals():
                await db.connectors.update_one(
                    {"tenant_id": tenant_id, "connector_id": connector_id},
                    {
                        "$set": {
                            "status": "error",
                            "last_error": str(e),
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
        except:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth callback failed"
        )


# Resource Operations

# PUBLIC_INTERFACE
@router.get("/{connector_id}/search", response_model=SearchResponse, summary="Search resources")
async def search_resources(
    connector_id: str,
    q: str = Query(..., description="Search query"),
    resource_type: Optional[str] = Query(None, description="Resource type to search"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Results per page"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Search resources in a connected service.
    
    Args:
        connector_id: Connector identifier
        q: Search query
        resource_type: Type of resource to search
        page: Page number
        per_page: Results per page
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        SearchResponse: Search results with pagination
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    # Get connector document
    connector_doc = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector_doc:
        raise ConnectorNotFoundException(connector_id)
    
    if connector_doc["status"] != "connected":
        raise ValidationException(f"Connector '{connector_id}' is not connected")
    
    try:
        # Get connector instance
        connector = connector_registry.create_connector(
            connector_id,
            connector_doc["config"]
        )
        
        # Decrypt credentials
        credentials = connector_doc.get("credentials", {})
        if credentials.get("access_token"):
            credentials["access_token"] = encryption_manager.decrypt(credentials["access_token"])
        if credentials.get("refresh_token"):
            credentials["refresh_token"] = encryption_manager.decrypt(credentials["refresh_token"])
        
        # Perform search
        results, total_count = await connector.search(
            credentials=credentials,
            query=q,
            resource_type=resource_type,
            page=page,
            per_page=per_page
        )
        
        return SearchResponse(
            results=results,
            total_count=total_count,
            page=page,
            per_page=per_page,
            has_more=total_count > (page * per_page)
        )
        
    except TokenExpiredException:
        # Try to refresh token
        try:
            await _refresh_connector_token(db, tenant_id, connector_id, connector)
            # Retry search with refreshed token
            # This is a simplified retry - in production you might want more sophisticated retry logic
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired, please retry request"
            )
        except Exception as refresh_error:
            logger.error(f"Failed to refresh token: {refresh_error}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication expired, please reconnect"
            )
    except Exception as e:
        logger.error(f"Search failed for {connector_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )


async def _refresh_connector_token(db, tenant_id: str, connector_id: str, connector: BaseConnector):
    """Helper function to refresh connector token"""
    connector_doc = await db.connectors.find_one({
        "tenant_id": tenant_id,
        "connector_id": connector_id
    })
    
    if not connector_doc or not connector_doc.get("credentials", {}).get("refresh_token"):
        raise TokenExpiredException(connector_id)
    
    credentials = connector_doc["credentials"]
    refresh_token = encryption_manager.decrypt(credentials["refresh_token"])
    
    # Refresh token
    token_data = await connector.refresh_access_token(tenant_id, refresh_token)
    
    # Update stored credentials
    new_credentials = {
        "access_token": encryption_manager.encrypt(token_data["access_token"]),
        "refresh_token": encryption_manager.encrypt(token_data.get("refresh_token", refresh_token)),
        "token_expires_at": datetime.utcnow().timestamp() + token_data.get("expires_in", 3600),
        "resources": credentials.get("resources", [])
    }
    
    await db.connectors.update_one(
        {"tenant_id": tenant_id, "connector_id": connector_id},
        {
            "$set": {
                "credentials": new_credentials,
                "updated_at": datetime.utcnow()
            }
        }
    )
