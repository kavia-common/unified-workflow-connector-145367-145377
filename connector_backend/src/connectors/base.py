from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from src.models.schemas import (
    ConnectorConfig, ConnectorMetadata, SearchResult, 
    AuthType, ResourceType
)


class BaseConnector(ABC):
    """
    Abstract base class for all connectors.
    
    This class defines the interface that all connectors must implement
    to ensure consistent behavior across different integrations.
    """
    
    # Connector identification
    id: str
    display_name: str
    connector_type: str
    version: str = "1.0.0"
    
    # Supported features
    supports_oauth: bool = True
    supports_webhooks: bool = False
    required_scopes: List[str] = []
    supported_auth_types: List[AuthType] = [AuthType.OAUTH2]
    supported_resources: List[ResourceType] = []
    
    def __init__(self, config: ConnectorConfig):
        """
        Initialize the connector with configuration.
        
        Args:
            config: Connector configuration
        """
        self.config = config
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def get_oauth_authorize_url(
        self, 
        tenant_id: str, 
        state: str,
        redirect_uri: str
    ) -> str:
        """
        Get OAuth authorization URL for the connector.
        
        Args:
            tenant_id: Tenant identifier
            state: OAuth state parameter for CSRF protection
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            str: Authorization URL
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def exchange_code_for_tokens(
        self, 
        tenant_id: str, 
        code: str, 
        state: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Exchange OAuth authorization code for access tokens.
        
        Args:
            tenant_id: Tenant identifier
            code: OAuth authorization code
            state: OAuth state parameter
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            dict: Token information including access_token, refresh_token, expires_in
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def refresh_access_token(
        self, 
        tenant_id: str, 
        refresh_token: str
    ) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Args:
            tenant_id: Tenant identifier
            refresh_token: OAuth refresh token
            
        Returns:
            dict: New token information
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Validate connector credentials.
        
        Args:
            credentials: Credential information to validate
            
        Returns:
            bool: True if credentials are valid
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def search(
        self, 
        credentials: Dict[str, Any],
        query: str, 
        resource_type: Optional[ResourceType] = None,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1, 
        per_page: int = 20
    ) -> Tuple[List[SearchResult], int]:
        """
        Search resources in the connected service.
        
        Args:
            credentials: Authentication credentials
            query: Search query string
            resource_type: Type of resource to search for
            filters: Additional search filters
            page: Page number for pagination
            per_page: Number of results per page
            
        Returns:
            tuple: (List of search results, total count)
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def get_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        resource_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific resource by ID.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to retrieve
            resource_id: Unique identifier of the resource
            
        Returns:
            dict: Resource data or None if not found
        """
        pass
    
    # PUBLIC_INTERFACE
    @abstractmethod
    async def create_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new resource.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to create
            data: Resource creation data
            
        Returns:
            dict: Created resource data
        """
        pass
    
    # PUBLIC_INTERFACE
    async def update_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        resource_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing resource.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to update
            resource_id: Unique identifier of the resource
            data: Resource update data
            
        Returns:
            dict: Updated resource data
        """
        raise NotImplementedError("Update operation not supported by this connector")
    
    # PUBLIC_INTERFACE
    async def delete_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        resource_id: str
    ) -> bool:
        """
        Delete a resource.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to delete
            resource_id: Unique identifier of the resource
            
        Returns:
            bool: True if deletion was successful
        """
        raise NotImplementedError("Delete operation not supported by this connector")
    
    # PUBLIC_INTERFACE
    async def get_resource_schema(self, resource_type: ResourceType) -> Dict[str, Any]:
        """
        Get the schema for a specific resource type.
        
        Args:
            resource_type: Type of resource
            
        Returns:
            dict: JSON schema for the resource type
        """
        return {
            "type": "object",
            "properties": {},
            "required": []
        }
    
    # PUBLIC_INTERFACE
    async def list_resources(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List resources of a specific type.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resources to list
            filters: Optional filters to apply
            page: Page number for pagination
            per_page: Number of results per page
            
        Returns:
            tuple: (List of resources, total count)
        """
        # Default implementation uses search with empty query
        results, total = await self.search(
            credentials=credentials,
            query="",
            resource_type=resource_type,
            filters=filters,
            page=page,
            per_page=per_page
        )
        return [result.model_dump() for result in results], total
    
    # PUBLIC_INTERFACE
    async def setup_webhook(
        self, 
        credentials: Dict[str, Any],
        webhook_url: str,
        events: List[str]
    ) -> Dict[str, Any]:
        """
        Setup webhook for the connector.
        
        Args:
            credentials: Authentication credentials
            webhook_url: URL to receive webhook events
            events: List of events to subscribe to
            
        Returns:
            dict: Webhook configuration details
        """
        if not self.supports_webhooks:
            raise NotImplementedError("Webhooks not supported by this connector")
        
        raise NotImplementedError("Webhook setup not implemented")
    
    # PUBLIC_INTERFACE
    async def process_webhook(
        self, 
        payload: Dict[str, Any],
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Process incoming webhook payload.
        
        Args:
            payload: Webhook payload data
            headers: HTTP headers from webhook request
            
        Returns:
            dict: Processed webhook data
        """
        if not self.supports_webhooks:
            raise NotImplementedError("Webhooks not supported by this connector")
        
        return {
            "event_type": "unknown",
            "processed_at": datetime.utcnow().isoformat(),
            "data": payload
        }
    
    # PUBLIC_INTERFACE
    def get_metadata(self) -> ConnectorMetadata:
        """
        Get connector metadata.
        
        Returns:
            ConnectorMetadata: Connector metadata
        """
        return ConnectorMetadata(
            display_name=self.display_name,
            description=f"{self.display_name} integration connector",
            version=self.version,
            supported_auth_types=self.supported_auth_types,
            supported_resources=self.supported_resources
        )
    
    # PUBLIC_INTERFACE
    async def test_connection(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test the connector connection.
        
        Args:
            credentials: Authentication credentials
            
        Returns:
            dict: Connection test results
        """
        try:
            is_valid = await self.validate_credentials(credentials)
            return {
                "status": "success" if is_valid else "failed",
                "message": "Connection successful" if is_valid else "Invalid credentials",
                "tested_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Connection test failed: {str(e)}",
                "tested_at": datetime.utcnow().isoformat()
            }
