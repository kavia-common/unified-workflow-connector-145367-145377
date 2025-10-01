from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from src.models.schemas import HealthStatus, MetricData, StatusResponse
from src.core.database import get_database
from src.core.security import get_current_user
from src.connectors.registry import connector_registry
from loguru import logger

router = APIRouter()


# PUBLIC_INTERFACE
@router.get("/health", response_model=HealthStatus, summary="System health check")
async def get_system_health(db = Depends(get_database)):
    """
    Get comprehensive system health status.
    
    Args:
        db: Database connection
        
    Returns:
        HealthStatus: System health information
    """
    health_checks = {}
    overall_status = "healthy"
    
    # Database health check
    try:
        await db.command("ping")
        health_checks["database"] = {
            "status": "healthy",
            "response_time_ms": 0,  # Could measure actual response time
            "message": "Database connection successful"
        }
    except Exception as e:
        health_checks["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "message": "Database connection failed"
        }
        overall_status = "unhealthy"
    
    # Connector registry health check
    try:
        connectors = await connector_registry.list_connectors()
        health_checks["connectors"] = {
            "status": "healthy",
            "count": len(connectors),
            "message": f"{len(connectors)} connectors registered"
        }
    except Exception as e:
        health_checks["connectors"] = {
            "status": "unhealthy",
            "error": str(e),
            "message": "Connector registry check failed"
        }
        if overall_status == "healthy":
            overall_status = "degraded"
    
    # Memory usage check (basic)
    import psutil
    try:
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        if memory_usage > 90:
            memory_status = "unhealthy"
            if overall_status == "healthy":
                overall_status = "degraded"
        elif memory_usage > 80:
            memory_status = "degraded"
            if overall_status == "healthy":
                overall_status = "degraded"
        else:
            memory_status = "healthy"
        
        health_checks["memory"] = {
            "status": memory_status,
            "usage_percent": memory_usage,
            "available_gb": round(memory.available / (1024**3), 2),
            "message": f"Memory usage: {memory_usage}%"
        }
    except Exception as e:
        health_checks["memory"] = {
            "status": "unknown",
            "error": str(e),
            "message": "Memory check failed"
        }
    
    return HealthStatus(
        status=overall_status,
        service="Unified Workflow Connector API",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        checks=health_checks
    )


# PUBLIC_INTERFACE
@router.get("/metrics", response_model=List[Dict[str, Any]], summary="Get system metrics")
async def get_metrics(
    metric_name: Optional[str] = Query(None, description="Filter by metric name"),
    hours: int = Query(24, ge=1, le=168, description="Hours of data to retrieve"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get system metrics data.
    
    Args:
        metric_name: Optional metric name filter
        hours: Hours of historical data to retrieve
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        List[dict]: Metrics data
    """
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Build query filter
        query_filter = {
            "data_points.timestamp": {
                "$gte": start_time,
                "$lte": end_time
            }
        }
        
        if metric_name:
            query_filter["metric_name"] = metric_name
        
        # Query metrics
        cursor = db.metrics.find(query_filter)
        metrics = []
        
        async for doc in cursor:
            # Filter data points by time range
            filtered_data_points = [
                dp for dp in doc.get("data_points", [])
                if start_time <= dp.get("timestamp", datetime.min) <= end_time
            ]
            
            metrics.append({
                "metric_name": doc["metric_name"],
                "metric_type": doc["metric_type"],
                "tenant_id": doc.get("tenant_id"),
                "data_points": [
                    {
                        "timestamp": dp["timestamp"].isoformat(),
                        "value": dp["value"],
                        "labels": dp.get("labels", {})
                    }
                    for dp in filtered_data_points
                ]
            })
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics"
        )


# PUBLIC_INTERFACE
@router.post("/metrics", response_model=StatusResponse, summary="Record metric")
async def record_metric(
    metric_name: str,
    metric_type: str,
    value: float,
    labels: Optional[Dict[str, str]] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Record a metric data point.
    
    Args:
        metric_name: Name of the metric
        metric_type: Type of metric (counter, gauge, histogram)
        value: Metric value
        labels: Optional metric labels
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Recording status
    """
    try:
        tenant_id = current_user.get("tenant_id")
        
        # Create metric data point
        data_point = MetricData(
            timestamp=datetime.utcnow(),
            value=value,
            labels=labels or {}
        )
        
        # Try to update existing metric or create new one
        await db.metrics.update_one(
            {
                "metric_name": metric_name,
                "tenant_id": tenant_id
            },
            {
                "$push": {"data_points": data_point.model_dump()},
                "$setOnInsert": {
                    "metric_name": metric_name,
                    "metric_type": metric_type,
                    "tenant_id": tenant_id
                }
            },
            upsert=True
        )
        
        return StatusResponse(
            status="success",
            message=f"Metric '{metric_name}' recorded successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to record metric: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record metric"
        )


# PUBLIC_INTERFACE
@router.get("/analytics/connectors", summary="Connector analytics")
async def get_connector_analytics(
    days: int = Query(30, ge=1, le=365, description="Days of data to analyze"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get connector usage analytics.
    
    Args:
        days: Days of historical data to analyze
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        dict: Connector analytics data
    """
    try:
        tenant_id = current_user.get("tenant_id")
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        # Get connector usage stats
        pipeline = [
            {
                "$match": {
                    "tenant_id": tenant_id,
                    "created_at": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": "$connector_id",
                    "count": {"$sum": 1},
                    "last_used": {"$max": "$last_sync_at"},
                    "statuses": {"$push": "$status"}
                }
            },
            {
                "$sort": {"count": -1}
            }
        ]
        
        connector_stats = []
        async for doc in db.connectors.aggregate(pipeline):
            # Calculate status distribution
            status_counts = {}
            for status_value in doc["statuses"]:
                status_counts[status_value] = status_counts.get(status_value, 0) + 1
            
            connector_stats.append({
                "connector_id": doc["_id"],
                "usage_count": doc["count"],
                "last_used": doc["last_used"].isoformat() if doc["last_used"] else None,
                "status_distribution": status_counts
            })
        
        # Get workflow analytics
        workflow_pipeline = [
            {
                "$match": {
                    "tenant_id": tenant_id,
                    "created_at": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        workflow_stats = {}
        async for doc in db.workflows.aggregate(workflow_pipeline):
            workflow_stats[doc["_id"]] = doc["count"]
        
        # Get error analytics
        error_pipeline = [
            {
                "$match": {
                    "tenant_id": tenant_id,
                    "last_error": {"$ne": None},
                    "updated_at": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": "$connector_id",
                    "error_count": {"$sum": 1},
                    "last_error": {"$last": "$last_error"}
                }
            }
        ]
        
        error_stats = []
        async for doc in db.connectors.aggregate(error_pipeline):
            error_stats.append({
                "connector_id": doc["_id"],
                "error_count": doc["error_count"],
                "last_error": doc["last_error"]
            })
        
        return {
            "period": {
                "start_date": start_time.isoformat(),
                "end_date": end_time.isoformat(),
                "days": days
            },
            "connector_usage": connector_stats,
            "workflow_status_distribution": workflow_stats,
            "error_summary": error_stats,
            "total_connectors": len(connector_stats),
            "total_workflows": sum(workflow_stats.values())
        }
        
    except Exception as e:
        logger.error(f"Failed to get connector analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve analytics"
        )


# PUBLIC_INTERFACE
@router.get("/analytics/performance", summary="Performance analytics")
async def get_performance_analytics(
    hours: int = Query(24, ge=1, le=168, description="Hours of data to analyze"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get system performance analytics.
    
    Args:
        hours: Hours of historical data to analyze
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        dict: Performance analytics data
    """
    try:
        tenant_id = current_user.get("tenant_id")
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Get API response time metrics
        response_time_pipeline = [
            {
                "$match": {
                    "metric_name": "api_response_time",
                    "tenant_id": tenant_id,
                    "data_points.timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$unwind": "$data_points"
            },
            {
                "$match": {
                    "data_points.timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": None,
                    "avg_response_time": {"$avg": "$data_points.value"},
                    "max_response_time": {"$max": "$data_points.value"},
                    "min_response_time": {"$min": "$data_points.value"},
                    "count": {"$sum": 1}
                }
            }
        ]
        
        response_time_stats = None
        async for doc in db.metrics.aggregate(response_time_pipeline):
            response_time_stats = {
                "average_ms": round(doc["avg_response_time"], 2),
                "maximum_ms": round(doc["max_response_time"], 2),
                "minimum_ms": round(doc["min_response_time"], 2),
                "total_requests": doc["count"]
            }
        
        # Get error rate metrics
        error_rate_pipeline = [
            {
                "$match": {
                    "metric_name": "api_errors",
                    "tenant_id": tenant_id,
                    "data_points.timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$unwind": "$data_points"
            },
            {
                "$match": {
                    "data_points.timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": None,
                    "total_errors": {"$sum": "$data_points.value"}
                }
            }
        ]
        
        total_errors = 0
        async for doc in db.metrics.aggregate(error_rate_pipeline):
            total_errors = doc["total_errors"]
        
        # Calculate error rate
        total_requests = response_time_stats["total_requests"] if response_time_stats else 0
        error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "period": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "hours": hours
            },
            "response_times": response_time_stats or {
                "average_ms": 0,
                "maximum_ms": 0,
                "minimum_ms": 0,
                "total_requests": 0
            },
            "error_rate": {
                "percentage": round(error_rate, 2),
                "total_errors": total_errors,
                "total_requests": total_requests
            },
            "uptime_percentage": 99.9  # This would be calculated from actual uptime metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get performance analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve performance analytics"
        )
