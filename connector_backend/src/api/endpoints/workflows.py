from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.models.schemas import (
    WorkflowResponse, WorkflowCreate, WorkflowUpdate,
    StatusResponse, WorkflowStatus
)
from src.core.database import get_database
from src.core.security import get_current_user
from src.core.exceptions import ValidationException, WorkflowException
from loguru import logger

router = APIRouter()


# PUBLIC_INTERFACE
@router.get("/", response_model=List[WorkflowResponse], summary="List workflows")
async def list_workflows(
    status_filter: Optional[WorkflowStatus] = Query(None, description="Filter by workflow status"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Results per page"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get list of workflows for the current tenant.
    
    Args:
        status_filter: Optional status filter
        page: Page number for pagination
        per_page: Results per page
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        List[WorkflowResponse]: List of workflows
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        # Build query filter
        query_filter = {"tenant_id": tenant_id}
        if status_filter:
            query_filter["status"] = status_filter
        
        # Calculate skip for pagination
        skip = (page - 1) * per_page
        
        # Query workflows
        cursor = db.workflows.find(query_filter).sort("created_at", -1).skip(skip).limit(per_page)
        workflows = []
        
        async for doc in cursor:
            workflows.append(WorkflowResponse(
                id=str(doc["_id"]),
                tenant_id=doc["tenant_id"],
                name=doc["name"],
                description=doc.get("description"),
                status=doc["status"],
                trigger=doc["trigger"],
                steps=doc["steps"],
                variables=doc.get("variables", {}),
                is_active=doc["is_active"],
                last_run_at=doc.get("last_run_at"),
                next_run_at=doc.get("next_run_at"),
                created_at=doc["created_at"],
                updated_at=doc.get("updated_at")
            ))
        
        return workflows
        
    except Exception as e:
        logger.error(f"Failed to list workflows: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflows"
        )


# PUBLIC_INTERFACE
@router.post("/", response_model=WorkflowResponse, summary="Create workflow")
async def create_workflow(
    workflow_data: WorkflowCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Create a new workflow.
    
    Args:
        workflow_data: Workflow creation data
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        WorkflowResponse: Created workflow
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        # Validate workflow steps
        await _validate_workflow_steps(workflow_data.steps, tenant_id, db)
        
        # Create workflow document
        workflow_doc = {
            "tenant_id": tenant_id,
            "name": workflow_data.name,
            "description": workflow_data.description,
            "status": WorkflowStatus.DRAFT,
            "trigger": workflow_data.trigger.model_dump(),
            "steps": [step.model_dump() for step in workflow_data.steps],
            "variables": workflow_data.variables,
            "is_active": True,
            "last_run_at": None,
            "next_run_at": None,
            "created_at": datetime.utcnow(),
            "updated_at": None
        }
        
        result = await db.workflows.insert_one(workflow_doc)
        
        # Retrieve created workflow
        created_workflow = await db.workflows.find_one({"_id": result.inserted_id})
        
        return WorkflowResponse(
            id=str(created_workflow["_id"]),
            tenant_id=created_workflow["tenant_id"],
            name=created_workflow["name"],
            description=created_workflow.get("description"),
            status=created_workflow["status"],
            trigger=created_workflow["trigger"],
            steps=created_workflow["steps"],
            variables=created_workflow.get("variables", {}),
            is_active=created_workflow["is_active"],
            last_run_at=created_workflow.get("last_run_at"),
            next_run_at=created_workflow.get("next_run_at"),
            created_at=created_workflow["created_at"],
            updated_at=created_workflow.get("updated_at")
        )
        
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Failed to create workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create workflow"
        )


# PUBLIC_INTERFACE
@router.get("/{workflow_id}", response_model=WorkflowResponse, summary="Get workflow")
async def get_workflow(
    workflow_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get a specific workflow by ID.
    
    Args:
        workflow_id: Workflow identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        WorkflowResponse: Workflow details
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        workflow = await db.workflows.find_one({
            "_id": ObjectId(workflow_id),
            "tenant_id": tenant_id
        })
        
        if not workflow:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        return WorkflowResponse(
            id=str(workflow["_id"]),
            tenant_id=workflow["tenant_id"],
            name=workflow["name"],
            description=workflow.get("description"),
            status=workflow["status"],
            trigger=workflow["trigger"],
            steps=workflow["steps"],
            variables=workflow.get("variables", {}),
            is_active=workflow["is_active"],
            last_run_at=workflow.get("last_run_at"),
            next_run_at=workflow.get("next_run_at"),
            created_at=workflow["created_at"],
            updated_at=workflow.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflow"
        )


# PUBLIC_INTERFACE
@router.put("/{workflow_id}", response_model=WorkflowResponse, summary="Update workflow")
async def update_workflow(
    workflow_id: str,
    update_data: WorkflowUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Update a workflow.
    
    Args:
        workflow_id: Workflow identifier
        update_data: Update data
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        WorkflowResponse: Updated workflow
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        # Check workflow exists
        workflow = await db.workflows.find_one({
            "_id": ObjectId(workflow_id),
            "tenant_id": tenant_id
        })
        
        if not workflow:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        # Build update document
        update_doc = {"updated_at": datetime.utcnow()}
        
        if update_data.name is not None:
            update_doc["name"] = update_data.name
        if update_data.description is not None:
            update_doc["description"] = update_data.description
        if update_data.status is not None:
            update_doc["status"] = update_data.status
        if update_data.trigger is not None:
            update_doc["trigger"] = update_data.trigger.model_dump()
        if update_data.steps is not None:
            # Validate steps if provided
            await _validate_workflow_steps(update_data.steps, tenant_id, db)
            update_doc["steps"] = [step.model_dump() for step in update_data.steps]
        if update_data.variables is not None:
            update_doc["variables"] = update_data.variables
        if update_data.is_active is not None:
            update_doc["is_active"] = update_data.is_active
        
        # Update workflow
        await db.workflows.update_one(
            {"_id": ObjectId(workflow_id), "tenant_id": tenant_id},
            {"$set": update_doc}
        )
        
        # Retrieve updated workflow
        updated_workflow = await db.workflows.find_one({
            "_id": ObjectId(workflow_id),
            "tenant_id": tenant_id
        })
        
        return WorkflowResponse(
            id=str(updated_workflow["_id"]),
            tenant_id=updated_workflow["tenant_id"],
            name=updated_workflow["name"],
            description=updated_workflow.get("description"),
            status=updated_workflow["status"],
            trigger=updated_workflow["trigger"],
            steps=updated_workflow["steps"],
            variables=updated_workflow.get("variables", {}),
            is_active=updated_workflow["is_active"],
            last_run_at=updated_workflow.get("last_run_at"),
            next_run_at=updated_workflow.get("next_run_at"),
            created_at=updated_workflow["created_at"],
            updated_at=updated_workflow.get("updated_at")
        )
        
    except (HTTPException, ValidationException):
        raise
    except Exception as e:
        logger.error(f"Failed to update workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update workflow"
        )


# PUBLIC_INTERFACE
@router.delete("/{workflow_id}", response_model=StatusResponse, summary="Delete workflow")
async def delete_workflow(
    workflow_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Delete a workflow.
    
    Args:
        workflow_id: Workflow identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Deletion status
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        # Delete workflow
        result = await db.workflows.delete_one({
            "_id": ObjectId(workflow_id),
            "tenant_id": tenant_id
        })
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        return StatusResponse(
            status="success",
            message=f"Workflow '{workflow_id}' deleted successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete workflow"
        )


# PUBLIC_INTERFACE
@router.post("/{workflow_id}/execute", response_model=StatusResponse, summary="Execute workflow")
async def execute_workflow(
    workflow_id: str,
    variables: Optional[Dict[str, Any]] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Execute a workflow manually.
    
    Args:
        workflow_id: Workflow identifier
        variables: Optional runtime variables
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Execution status
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        # Get workflow
        workflow = await db.workflows.find_one({
            "_id": ObjectId(workflow_id),
            "tenant_id": tenant_id
        })
        
        if not workflow:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        if not workflow["is_active"]:
            raise WorkflowException("Workflow is not active", workflow_id)
        
        # TODO: Implement actual workflow execution logic
        # This is a placeholder for the workflow execution engine
        
        # Update workflow with execution info
        await db.workflows.update_one(
            {"_id": ObjectId(workflow_id)},
            {
                "$set": {
                    "last_run_at": datetime.utcnow(),
                    "status": WorkflowStatus.ACTIVE
                }
            }
        )
        
        # Create workflow execution record
        execution_doc = {
            "workflow_id": ObjectId(workflow_id),
            "tenant_id": tenant_id,
            "user_id": current_user.get("user_id"),
            "status": "running",
            "variables": variables or {},
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "error": None,
            "steps_completed": 0,
            "total_steps": len(workflow.get("steps", []))
        }
        
        await db.workflow_executions.insert_one(execution_doc)
        
        return StatusResponse(
            status="success",
            message=f"Workflow '{workflow_id}' execution started"
        )
        
    except (HTTPException, WorkflowException):
        raise
    except Exception as e:
        logger.error(f"Failed to execute workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute workflow"
        )


# PUBLIC_INTERFACE
@router.post("/{workflow_id}/activate", response_model=StatusResponse, summary="Activate workflow")
async def activate_workflow(
    workflow_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Activate a workflow to enable automatic execution.
    
    Args:
        workflow_id: Workflow identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Activation status
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        # Update workflow status
        result = await db.workflows.update_one(
            {
                "_id": ObjectId(workflow_id),
                "tenant_id": tenant_id
            },
            {
                "$set": {
                    "status": WorkflowStatus.ACTIVE,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        return StatusResponse(
            status="success",
            message=f"Workflow '{workflow_id}' activated successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate workflow"
        )


# PUBLIC_INTERFACE
@router.post("/{workflow_id}/deactivate", response_model=StatusResponse, summary="Deactivate workflow")
async def deactivate_workflow(
    workflow_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Deactivate a workflow to stop automatic execution.
    
    Args:
        workflow_id: Workflow identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Deactivation status
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise ValidationException("No tenant ID found in token")
    
    try:
        from bson import ObjectId
        
        # Update workflow status
        result = await db.workflows.update_one(
            {
                "_id": ObjectId(workflow_id),
                "tenant_id": tenant_id
            },
            {
                "$set": {
                    "status": WorkflowStatus.PAUSED,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workflow not found"
            )
        
        return StatusResponse(
            status="success",
            message=f"Workflow '{workflow_id}' deactivated successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate workflow: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate workflow"
        )


async def _validate_workflow_steps(steps: List[Any], tenant_id: str, db) -> None:
    """
    Validate workflow steps.
    
    Args:
        steps: List of workflow steps to validate
        tenant_id: Tenant identifier
        db: Database connection
        
    Raises:
        ValidationException: If validation fails
    """
    from src.connectors.registry import connector_registry
    
    for step in steps:
        step_dict = step.model_dump() if hasattr(step, 'model_dump') else step
        action = step_dict.get("action", {})
        connector_id = action.get("connector_id")
        
        if not connector_id:
            raise ValidationException(f"Step '{step_dict.get('name')}' missing connector_id")
        
        # Check if connector is registered
        if not connector_registry.is_registered(connector_id):
            raise ValidationException(f"Connector '{connector_id}' is not registered")
        
        # Check if connector is configured for tenant
        connector_doc = await db.connectors.find_one({
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "is_active": True
        })
        
        if not connector_doc:
            raise ValidationException(f"Connector '{connector_id}' is not configured for this tenant")
        
        if connector_doc["status"] != "connected":
            raise ValidationException(f"Connector '{connector_id}' is not connected")
