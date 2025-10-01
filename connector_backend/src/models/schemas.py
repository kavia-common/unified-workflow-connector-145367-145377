from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId


class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic models"""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


class ConnectorStatus(str, Enum):
    """Connector status enumeration"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    PENDING = "pending"


class AuthType(str, Enum):
    """Authentication type enumeration"""
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"


class ResourceType(str, Enum):
    """Resource type enumeration"""
    ISSUE = "issue"
    PAGE = "page"
    PROJECT = "project"
    SPACE = "space"
    REPOSITORY = "repository"
    CHANNEL = "channel"
    TICKET = "ticket"
    USER = "user"


class WorkflowStatus(str, Enum):
    """Workflow status enumeration"""
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class EventType(str, Enum):
    """Event type enumeration"""
    WEBHOOK = "webhook"
    SCHEDULE = "schedule"
    MANUAL = "manual"


# Base Models
class BaseSchema(BaseModel):
    """Base schema with common configuration"""
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields"""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


# Connector Models
class ConnectorConfig(BaseSchema):
    """Connector configuration model"""
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    scopes: List[str] = []
    custom_fields: Dict[str, Any] = {}


class ConnectorCredentials(BaseSchema):
    """Connector credentials model (encrypted)"""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    encrypted_data: Optional[str] = None


class ConnectorMetadata(BaseSchema):
    """Connector metadata model"""
    display_name: str
    description: Optional[str] = None
    icon_url: Optional[str] = None
    version: str = "1.0.0"
    supported_auth_types: List[AuthType] = []
    supported_resources: List[ResourceType] = []
    webhook_url: Optional[str] = None


class Connector(BaseSchema, TimestampMixin):
    """Main connector model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    tenant_id: str
    connector_id: str  # e.g., "jira", "confluence"
    connector_type: str  # e.g., "atlassian", "github"
    status: ConnectorStatus = ConnectorStatus.DISCONNECTED
    auth_type: AuthType
    config: ConnectorConfig
    credentials: Optional[ConnectorCredentials] = None
    metadata: ConnectorMetadata
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    is_active: bool = True


class ConnectorCreate(BaseSchema):
    """Schema for creating a connector"""
    connector_id: str
    connector_type: str
    auth_type: AuthType
    config: ConnectorConfig
    metadata: ConnectorMetadata


class ConnectorUpdate(BaseSchema):
    """Schema for updating a connector"""
    status: Optional[ConnectorStatus] = None
    config: Optional[ConnectorConfig] = None
    metadata: Optional[ConnectorMetadata] = None
    is_active: Optional[bool] = None


class ConnectorResponse(BaseSchema):
    """Schema for connector API responses"""
    id: str
    tenant_id: str
    connector_id: str
    connector_type: str
    status: ConnectorStatus
    auth_type: AuthType
    metadata: ConnectorMetadata
    last_sync_at: Optional[datetime] = None
    last_error: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None


# OAuth Models
class OAuthLoginRequest(BaseSchema):
    """OAuth login request schema"""
    return_url: Optional[str] = None


class OAuthLoginResponse(BaseSchema):
    """OAuth login response schema"""
    authorization_url: str
    state: str


class OAuthCallbackQuery(BaseSchema):
    """OAuth callback query parameters"""
    code: str
    state: str
    error: Optional[str] = None
    error_description: Optional[str] = None


# Search and Resource Models
class SearchResult(BaseSchema):
    """Generic search result model"""
    id: str
    title: str
    url: Optional[str] = None
    type: ResourceType
    subtitle: Optional[str] = None
    metadata: Dict[str, Any] = {}


class SearchResponse(BaseSchema):
    """Search response with pagination"""
    results: List[SearchResult]
    total_count: int
    page: int = 1
    per_page: int = 20
    has_more: bool = False


# Workflow Models
class WorkflowTrigger(BaseSchema):
    """Workflow trigger configuration"""
    type: EventType
    connector_id: Optional[str] = None
    event_filter: Dict[str, Any] = {}
    schedule: Optional[str] = None  # Cron expression for scheduled triggers


class WorkflowAction(BaseSchema):
    """Workflow action configuration"""
    connector_id: str
    action_type: str  # e.g., "create_issue", "send_message"
    parameters: Dict[str, Any] = {}
    condition: Optional[Dict[str, Any]] = None


class WorkflowStep(BaseSchema):
    """Individual workflow step"""
    id: str
    name: str
    action: WorkflowAction
    depends_on: List[str] = []  # IDs of prerequisite steps
    retry_config: Optional[Dict[str, Any]] = None


class Workflow(BaseSchema, TimestampMixin):
    """Main workflow model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    tenant_id: str
    name: str
    description: Optional[str] = None
    status: WorkflowStatus = WorkflowStatus.DRAFT
    trigger: WorkflowTrigger
    steps: List[WorkflowStep] = []
    variables: Dict[str, Any] = {}
    is_active: bool = True
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None


class WorkflowCreate(BaseSchema):
    """Schema for creating a workflow"""
    name: str
    description: Optional[str] = None
    trigger: WorkflowTrigger
    steps: List[WorkflowStep] = []
    variables: Dict[str, Any] = {}


class WorkflowUpdate(BaseSchema):
    """Schema for updating a workflow"""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[WorkflowStatus] = None
    trigger: Optional[WorkflowTrigger] = None
    steps: Optional[List[WorkflowStep]] = None
    variables: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class WorkflowResponse(BaseSchema):
    """Schema for workflow API responses"""
    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    status: WorkflowStatus
    trigger: WorkflowTrigger
    steps: List[WorkflowStep]
    variables: Dict[str, Any]
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


# Webhook Models
class WebhookEvent(BaseSchema, TimestampMixin):
    """Webhook event model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    tenant_id: str
    connector_id: str
    event_type: str
    event_data: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    processed: bool = False
    processing_error: Optional[str] = None


class WebhookEventCreate(BaseSchema):
    """Schema for creating webhook events"""
    connector_id: str
    event_type: str
    event_data: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


# Monitoring Models
class MetricData(BaseSchema):
    """Metric data point"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    value: Union[int, float]
    labels: Dict[str, str] = {}


class Metric(BaseSchema):
    """Metric model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    tenant_id: Optional[str] = None
    metric_name: str
    metric_type: str  # counter, gauge, histogram
    data_points: List[MetricData] = []


class HealthStatus(BaseSchema):
    """Health status model"""
    status: str  # healthy, degraded, unhealthy
    service: str
    version: str
    timestamp: datetime
    checks: Dict[str, Dict[str, Any]] = {}


# Audit Models
class AuditLog(BaseSchema, TimestampMixin):
    """Audit log model"""
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    tenant_id: str
    user_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None


# WebSocket Models
class WebSocketMessage(BaseSchema):
    """WebSocket message model"""
    type: str
    data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ConnectionInfo(BaseSchema):
    """WebSocket connection information"""
    connection_id: str
    tenant_id: str
    user_id: Optional[str] = None
    connected_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)


# API Response Models
class StatusResponse(BaseSchema):
    """Generic status response"""
    status: str
    message: str
    request_id: Optional[str] = None


class ErrorResponse(BaseSchema):
    """Error response model"""
    status: str = "error"
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


class PaginatedResponse(BaseSchema):
    """Generic paginated response"""
    items: List[Any]
    total_count: int
    page: int
    per_page: int
    total_pages: int
    has_next: bool
    has_previous: bool
