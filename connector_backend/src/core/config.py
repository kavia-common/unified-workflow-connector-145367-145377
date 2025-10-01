from functools import lru_cache
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings can be configured via environment variables with the same name.
    """
    
    # Application settings
    APP_NAME: str = "Unified Workflow Connector"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    
    # API settings
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = Field(..., description="Secret key for JWT token generation")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Security settings
    ALLOWED_ORIGINS: List[str] = ["*"]
    ALLOWED_HOSTS: Optional[List[str]] = None
    
    # Database settings
    MONGODB_URL: str = Field(..., description="MongoDB connection URL")
    MONGODB_DB_NAME: str = "workflow_connector"
    
    # Redis settings (for caching and job queue)
    REDIS_URL: str = "redis://localhost:6379"
    
    # Encryption settings
    ENCRYPTION_KEY: str = Field(..., description="Key for encrypting sensitive data")
    
    # OAuth Provider Settings
    # JIRA/Atlassian
    JIRA_CLIENT_ID: Optional[str] = None
    JIRA_CLIENT_SECRET: Optional[str] = None
    JIRA_REDIRECT_URI: Optional[str] = None
    
    # Confluence
    CONFLUENCE_CLIENT_ID: Optional[str] = None
    CONFLUENCE_CLIENT_SECRET: Optional[str] = None
    CONFLUENCE_REDIRECT_URI: Optional[str] = None
    
    # Slack
    SLACK_CLIENT_ID: Optional[str] = None
    SLACK_CLIENT_SECRET: Optional[str] = None
    SLACK_REDIRECT_URI: Optional[str] = None
    
    # GitHub
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    GITHUB_REDIRECT_URI: Optional[str] = None
    
    # GitLab
    GITLAB_CLIENT_ID: Optional[str] = None
    GITLAB_CLIENT_SECRET: Optional[str] = None
    GITLAB_REDIRECT_URI: Optional[str] = None
    
    # ServiceNow
    SERVICENOW_CLIENT_ID: Optional[str] = None
    SERVICENOW_CLIENT_SECRET: Optional[str] = None
    SERVICENOW_REDIRECT_URI: Optional[str] = None
    
    # Webhook settings
    WEBHOOK_SECRET: Optional[str] = Field(None, description="Secret for webhook validation")
    
    # Monitoring settings
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 100
    
    # Background job settings
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    
    # WebSocket settings
    WS_MAX_CONNECTIONS: int = 1000
    WS_HEARTBEAT_INTERVAL: int = 30
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# PUBLIC_INTERFACE
@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Returns:
        Settings: Application settings
    """
    return Settings()


settings = get_settings()
