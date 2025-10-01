from fastapi import APIRouter, HTTPException, status, Depends, Request, Header
from typing import Dict, Any, Optional, List
from datetime import datetime
import hmac
import hashlib

from src.models.schemas import WebhookEventCreate, StatusResponse
from src.core.database import get_database
from src.core.exceptions import ValidationException, ConnectorNotFoundException
from src.connectors.registry import connector_registry
from src.core.config import settings
from loguru import logger

router = APIRouter()


# PUBLIC_INTERFACE
@router.post("/{connector_id}", response_model=StatusResponse, summary="Receive webhook")
async def receive_webhook(
    connector_id: str,
    request: Request,
    payload: Dict[str, Any],
    x_hub_signature: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
    x_slack_signature: Optional[str] = Header(None),
    user_agent: Optional[str] = Header(None),
    db = Depends(get_database)
):
    """
    Receive and process webhook events from external services.
    
    Args:
        connector_id: Connector identifier
        request: FastAPI request object
        payload: Webhook payload data
        x_hub_signature: GitHub webhook signature
        x_github_event: GitHub event type
        x_slack_signature: Slack webhook signature
        user_agent: User agent header
        db: Database connection
        
    Returns:
        StatusResponse: Webhook processing status
    """
    try:
        # Get client IP
        client_ip = request.client.host if request.client else None
        
        # Validate connector exists and supports webhooks
        if not connector_registry.is_registered(connector_id):
            raise ConnectorNotFoundException(connector_id)
        
        connector_class = connector_registry.get_connector_class(connector_id)
        if not connector_class.supports_webhooks:
            raise ValidationException(f"Connector '{connector_id}' does not support webhooks")
        
        # Validate webhook signature if required
        await _validate_webhook_signature(
            connector_id, 
            payload, 
            x_hub_signature, 
            x_slack_signature,
            request
        )
        
        # Determine event type
        event_type = _determine_event_type(
            connector_id, 
            payload, 
            x_github_event,
            request.headers
        )
        
        # Store webhook event
        webhook_event = WebhookEventCreate(
            connector_id=connector_id,
            event_type=event_type,
            event_data=payload,
            source_ip=client_ip,
            user_agent=user_agent
        )
        
        event_doc = {
            "connector_id": webhook_event.connector_id,
            "event_type": webhook_event.event_type,
            "event_data": webhook_event.event_data,
            "source_ip": webhook_event.source_ip,
            "user_agent": webhook_event.user_agent,
            "processed": False,
            "processing_error": None,
            "created_at": datetime.utcnow()
        }
        
        result = await db.webhook_events.insert_one(event_doc)
        
        # TODO: Trigger workflow processing based on event
        # This would typically be done asynchronously via a job queue
        
        logger.info(
            f"Webhook received for {connector_id}",
            extra={
                "connector_id": connector_id,
                "event_type": event_type,
                "event_id": str(result.inserted_id),
                "source_ip": client_ip
            }
        )
        
        return StatusResponse(
            status="success",
            message="Webhook received and queued for processing"
        )
        
    except (ConnectorNotFoundException, ValidationException):
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed for {connector_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


# PUBLIC_INTERFACE
@router.get("/events", response_model=List[Dict[str, Any]], summary="List webhook events")
async def list_webhook_events(
    connector_id: Optional[str] = None,
    event_type: Optional[str] = None,
    processed: Optional[bool] = None,
    limit: int = 50,
    db = Depends(get_database)
):
    """
    List webhook events with optional filtering.
    
    Args:
        connector_id: Filter by connector ID
        event_type: Filter by event type
        processed: Filter by processing status
        limit: Maximum number of events to return
        db: Database connection
        
    Returns:
        List[dict]: Webhook events
    """
    try:
        # Build query filter
        query_filter = {}
        
        if connector_id:
            query_filter["connector_id"] = connector_id
        if event_type:
            query_filter["event_type"] = event_type
        if processed is not None:
            query_filter["processed"] = processed
        
        # Query events
        cursor = db.webhook_events.find(query_filter).sort("created_at", -1).limit(limit)
        events = []
        
        async for doc in cursor:
            events.append({
                "id": str(doc["_id"]),
                "connector_id": doc["connector_id"],
                "event_type": doc["event_type"],
                "event_data": doc["event_data"],
                "source_ip": doc.get("source_ip"),
                "user_agent": doc.get("user_agent"),
                "processed": doc["processed"],
                "processing_error": doc.get("processing_error"),
                "created_at": doc["created_at"].isoformat()
            })
        
        return events
        
    except Exception as e:
        logger.error(f"Failed to list webhook events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve webhook events"
        )


# PUBLIC_INTERFACE
@router.post("/events/{event_id}/reprocess", response_model=StatusResponse, summary="Reprocess webhook event")
async def reprocess_webhook_event(
    event_id: str,
    db = Depends(get_database)
):
    """
    Reprocess a failed webhook event.
    
    Args:
        event_id: Webhook event identifier
        db: Database connection
        
    Returns:
        StatusResponse: Reprocessing status
    """
    try:
        from bson import ObjectId
        
        # Get webhook event
        event = await db.webhook_events.find_one({"_id": ObjectId(event_id)})
        
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Webhook event not found"
            )
        
        # Reset processing status
        await db.webhook_events.update_one(
            {"_id": ObjectId(event_id)},
            {
                "$set": {
                    "processed": False,
                    "processing_error": None,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # TODO: Queue event for reprocessing
        
        return StatusResponse(
            status="success",
            message="Webhook event queued for reprocessing"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reprocess webhook event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reprocess webhook event"
        )


async def _validate_webhook_signature(
    connector_id: str,
    payload: Dict[str, Any],
    github_signature: Optional[str],
    slack_signature: Optional[str],
    request: Request
) -> None:
    """
    Validate webhook signature for security.
    
    Args:
        connector_id: Connector identifier
        payload: Webhook payload
        github_signature: GitHub signature header
        slack_signature: Slack signature header
        request: FastAPI request object
        
    Raises:
        ValidationException: If signature validation fails
    """
    if not settings.WEBHOOK_SECRET:
        # Skip validation if no secret is configured
        return
    
    body = await request.body()
    
    if connector_id == "github" and github_signature:
        # Validate GitHub webhook signature
        expected_signature = hmac.new(
            settings.WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(f"sha256={expected_signature}", github_signature):
            raise ValidationException("Invalid webhook signature")
    
    elif connector_id == "slack" and slack_signature:
        # Validate Slack webhook signature
        timestamp = request.headers.get("X-Slack-Request-Timestamp")
        if not timestamp:
            raise ValidationException("Missing Slack timestamp")
        
        sig_basestring = f"v0:{timestamp}:{body.decode()}"
        expected_signature = hmac.new(
            settings.WEBHOOK_SECRET.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(f"v0={expected_signature}", slack_signature):
            raise ValidationException("Invalid webhook signature")


def _determine_event_type(
    connector_id: str,
    payload: Dict[str, Any],
    github_event: Optional[str],
    headers: Dict[str, str]
) -> str:
    """
    Determine the event type from the webhook payload.
    
    Args:
        connector_id: Connector identifier
        payload: Webhook payload
        github_event: GitHub event header
        headers: Request headers
        
    Returns:
        str: Event type
    """
    if connector_id == "github":
        return github_event or "unknown"
    elif connector_id == "jira":
        return payload.get("webhookEvent", "unknown")
    elif connector_id == "confluence":
        return payload.get("eventType", "unknown")
    elif connector_id == "slack":
        if payload.get("type") == "url_verification":
            return "url_verification"
        return payload.get("event", {}).get("type", "unknown")
    else:
        return "unknown"
