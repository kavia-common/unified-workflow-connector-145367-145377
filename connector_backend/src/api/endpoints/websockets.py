from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from typing import Dict, Any, List, Optional
import json
from datetime import datetime

from src.models.schemas import WebSocketMessage, ConnectionInfo
from src.core.database import get_database
from src.core.security import token_manager
from src.core.exceptions import AuthenticationException
from loguru import logger

router = APIRouter()


class ConnectionManager:
    """WebSocket connection manager"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.tenant_connections: Dict[str, List[str]] = {}
        self.connection_info: Dict[str, ConnectionInfo] = {}
    
    async def connect(self, websocket: WebSocket, connection_id: str, tenant_id: str, user_id: Optional[str] = None):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        
        self.active_connections[connection_id] = websocket
        self.connection_info[connection_id] = ConnectionInfo(
            connection_id=connection_id,
            tenant_id=tenant_id,
            user_id=user_id
        )
        
        # Add to tenant connections
        if tenant_id not in self.tenant_connections:
            self.tenant_connections[tenant_id] = []
        self.tenant_connections[tenant_id].append(connection_id)
        
        logger.info(f"WebSocket connection established: {connection_id}")
    
    def disconnect(self, connection_id: str):
        """Remove a WebSocket connection"""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        if connection_id in self.connection_info:
            tenant_id = self.connection_info[connection_id].tenant_id
            
            # Remove from tenant connections
            if tenant_id in self.tenant_connections:
                self.tenant_connections[tenant_id] = [
                    cid for cid in self.tenant_connections[tenant_id] 
                    if cid != connection_id
                ]
                
                # Clean up empty tenant lists
                if not self.tenant_connections[tenant_id]:
                    del self.tenant_connections[tenant_id]
            
            del self.connection_info[connection_id]
        
        logger.info(f"WebSocket connection closed: {connection_id}")
    
    async def send_personal_message(self, message: str, connection_id: str):
        """Send a message to a specific connection"""
        if connection_id in self.active_connections:
            try:
                await self.active_connections[connection_id].send_text(message)
            except Exception as e:
                logger.error(f"Failed to send message to {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def send_tenant_message(self, message: str, tenant_id: str):
        """Send a message to all connections for a tenant"""
        if tenant_id in self.tenant_connections:
            connections_to_remove = []
            
            for connection_id in self.tenant_connections[tenant_id]:
                try:
                    await self.active_connections[connection_id].send_text(message)
                except Exception as e:
                    logger.error(f"Failed to send message to {connection_id}: {e}")
                    connections_to_remove.append(connection_id)
            
            # Clean up failed connections
            for connection_id in connections_to_remove:
                self.disconnect(connection_id)
    
    async def broadcast(self, message: str):
        """Broadcast a message to all connections"""
        connections_to_remove = []
        
        for connection_id, websocket in self.active_connections.items():
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to {connection_id}: {e}")
                connections_to_remove.append(connection_id)
        
        # Clean up failed connections
        for connection_id in connections_to_remove:
            self.disconnect(connection_id)
    
    def get_tenant_connections(self, tenant_id: str) -> List[str]:
        """Get all connection IDs for a tenant"""
        return self.tenant_connections.get(tenant_id, [])
    
    def get_connection_count(self) -> int:
        """Get total number of active connections"""
        return len(self.active_connections)


# Global connection manager
manager = ConnectionManager()


async def authenticate_websocket(token: str) -> Dict[str, Any]:
    """
    Authenticate WebSocket connection using JWT token.
    
    Args:
        token: JWT token
        
    Returns:
        dict: User information
        
    Raises:
        AuthenticationException: If authentication fails
    """
    try:
        payload = token_manager.verify_token(token)
        return payload
    except Exception as e:
        raise AuthenticationException(f"WebSocket authentication failed: {e}")


# PUBLIC_INTERFACE
@router.websocket("/connect")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str,
    db = Depends(get_database)
):
    """
    WebSocket endpoint for real-time communication.
    
    This endpoint handles real-time updates for:
    - Workflow execution status
    - Connector connection status
    - System notifications
    - Live analytics data
    
    Args:
        websocket: WebSocket connection
        token: JWT authentication token
        db: Database connection
    """
    connection_id = None
    
    try:
        # Authenticate user
        user_info = await authenticate_websocket(token)
        tenant_id = user_info.get("tenant_id")
        user_id = user_info.get("user_id")
        
        if not tenant_id:
            await websocket.close(code=1008, reason="No tenant ID in token")
            return
        
        # Generate connection ID
        import uuid
        connection_id = str(uuid.uuid4())
        
        # Accept connection
        await manager.connect(websocket, connection_id, tenant_id, user_id)
        
        # Send welcome message
        welcome_message = WebSocketMessage(
            type="connection_established",
            data={
                "connection_id": connection_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "message": "WebSocket connection established"
            }
        )
        
        await websocket.send_text(welcome_message.model_dump_json())
        
        # Listen for messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle different message types
                await handle_websocket_message(
                    connection_id, 
                    tenant_id, 
                    user_id, 
                    message_data, 
                    db
                )
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                error_message = WebSocketMessage(
                    type="error",
                    data={"message": "Invalid JSON format"}
                )
                await websocket.send_text(error_message.model_dump_json())
            except Exception as e:
                logger.error(f"WebSocket message handling error: {e}")
                error_message = WebSocketMessage(
                    type="error",
                    data={"message": "Message processing failed"}
                )
                await websocket.send_text(error_message.model_dump_json())
    
    except AuthenticationException as e:
        await websocket.close(code=1008, reason=str(e))
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        await websocket.close(code=1011, reason="Internal server error")
    finally:
        if connection_id:
            manager.disconnect(connection_id)


async def handle_websocket_message(
    connection_id: str,
    tenant_id: str,
    user_id: Optional[str],
    message_data: Dict[str, Any],
    db
) -> None:
    """
    Handle incoming WebSocket messages.
    
    Args:
        connection_id: WebSocket connection identifier
        tenant_id: Tenant identifier
        user_id: User identifier
        message_data: Message data
        db: Database connection
    """
    message_type = message_data.get("type")
    
    if message_type == "ping":
        # Handle ping/pong for connection keepalive
        pong_message = WebSocketMessage(
            type="pong",
            data={"timestamp": datetime.utcnow().isoformat()}
        )
        await manager.send_personal_message(pong_message.model_dump_json(), connection_id)
    
    elif message_type == "subscribe":
        # Handle subscription to specific data streams
        topics = message_data.get("topics", [])
        
        # Store subscription preferences (in a real implementation)
        # For now, just acknowledge
        response_message = WebSocketMessage(
            type="subscription_confirmed",
            data={
                "topics": topics,
                "message": f"Subscribed to {len(topics)} topics"
            }
        )
        await manager.send_personal_message(response_message.model_dump_json(), connection_id)
    
    elif message_type == "unsubscribe":
        # Handle unsubscription from data streams
        topics = message_data.get("topics", [])
        
        response_message = WebSocketMessage(
            type="unsubscription_confirmed",
            data={
                "topics": topics,
                "message": f"Unsubscribed from {len(topics)} topics"
            }
        )
        await manager.send_personal_message(response_message.model_dump_json(), connection_id)
    
    elif message_type == "get_status":
        # Handle status request
        status_data = {
            "connection_id": connection_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "active_connections": manager.get_connection_count(),
            "tenant_connections": len(manager.get_tenant_connections(tenant_id)),
            "server_time": datetime.utcnow().isoformat()
        }
        
        status_message = WebSocketMessage(
            type="status_response",
            data=status_data
        )
        await manager.send_personal_message(status_message.model_dump_json(), connection_id)


# PUBLIC_INTERFACE
@router.post("/broadcast", summary="Broadcast message")
async def broadcast_message(
    message_type: str,
    data: Dict[str, Any],
    tenant_id: Optional[str] = None
):
    """
    Broadcast a message to WebSocket connections.
    
    This endpoint is typically used by internal services to send
    real-time updates to connected clients.
    
    Args:
        message_type: Type of message
        data: Message data
        tenant_id: Optional tenant ID to limit broadcast scope
        
    Returns:
        dict: Broadcast status
    """
    try:
        message = WebSocketMessage(
            type=message_type,
            data=data
        )
        
        if tenant_id:
            await manager.send_tenant_message(message.model_dump_json(), tenant_id)
            connection_count = len(manager.get_tenant_connections(tenant_id))
        else:
            await manager.broadcast(message.model_dump_json())
            connection_count = manager.get_connection_count()
        
        return {
            "status": "success",
            "message": f"Message broadcasted to {connection_count} connections",
            "message_type": message_type,
            "tenant_scope": tenant_id is not None
        }
        
    except Exception as e:
        logger.error(f"Broadcast failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Broadcast failed"
        )


# PUBLIC_INTERFACE
@router.get("/connections", summary="Get connection status")
async def get_connection_status():
    """
    Get WebSocket connection statistics.
    
    Returns:
        dict: Connection statistics
    """
    try:
        tenant_stats = {}
        for tenant_id, connections in manager.tenant_connections.items():
            tenant_stats[tenant_id] = len(connections)
        
        return {
            "total_connections": manager.get_connection_count(),
            "tenant_distribution": tenant_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get connection status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve connection status"
        )


# Function to send real-time updates (used by other services)
async def send_workflow_update(tenant_id: str, workflow_id: str, status: str, data: Dict[str, Any]):
    """Send workflow status update to tenant connections"""
    message = WebSocketMessage(
        type="workflow_update",
        data={
            "workflow_id": workflow_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
    )
    await manager.send_tenant_message(message.model_dump_json(), tenant_id)


async def send_connector_update(tenant_id: str, connector_id: str, status: str, data: Dict[str, Any]):
    """Send connector status update to tenant connections"""
    message = WebSocketMessage(
        type="connector_update",
        data={
            "connector_id": connector_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
    )
    await manager.send_tenant_message(message.model_dump_json(), tenant_id)


async def send_system_notification(tenant_id: str, notification_type: str, title: str, message: str):
    """Send system notification to tenant connections"""
    notification = WebSocketMessage(
        type="system_notification",
        data={
            "notification_type": notification_type,
            "title": title,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    await manager.send_tenant_message(notification.model_dump_json(), tenant_id)
