from typing import Dict, List, Optional, Type
from loguru import logger

from src.connectors.base import BaseConnector
from src.models.schemas import ConnectorMetadata
from src.core.exceptions import ConnectorNotFoundException


class ConnectorRegistry:
    """
    Registry for managing available connectors.
    
    This class maintains a registry of all available connectors and provides
    methods to discover, register, and instantiate connectors.
    """
    
    def __init__(self):
        self._connectors: Dict[str, Type[BaseConnector]] = {}
        self._metadata: Dict[str, ConnectorMetadata] = {}
    
    # PUBLIC_INTERFACE
    def register(self, connector_class: Type[BaseConnector]) -> None:
        """
        Register a connector class.
        
        Args:
            connector_class: Connector class to register
        """
        connector_id = connector_class.id
        
        if connector_id in self._connectors:
            logger.warning(f"Connector '{connector_id}' is already registered, overriding")
        
        self._connectors[connector_id] = connector_class
        
        # Create a temporary instance to get metadata
        try:
            from src.models.schemas import ConnectorConfig
            temp_instance = connector_class(ConnectorConfig())
            self._metadata[connector_id] = temp_instance.get_metadata()
            logger.info(f"Registered connector: {connector_id}")
        except Exception as e:
            logger.error(f"Failed to get metadata for connector '{connector_id}': {e}")
    
    # PUBLIC_INTERFACE
    def get_connector_class(self, connector_id: str) -> Type[BaseConnector]:
        """
        Get a connector class by ID.
        
        Args:
            connector_id: Connector identifier
            
        Returns:
            Type[BaseConnector]: Connector class
            
        Raises:
            ConnectorNotFoundException: If connector is not found
        """
        if connector_id not in self._connectors:
            raise ConnectorNotFoundException(connector_id)
        
        return self._connectors[connector_id]
    
    # PUBLIC_INTERFACE
    def create_connector(self, connector_id: str, config) -> BaseConnector:
        """
        Create a connector instance.
        
        Args:
            connector_id: Connector identifier
            config: Connector configuration
            
        Returns:
            BaseConnector: Connector instance
            
        Raises:
            ConnectorNotFoundException: If connector is not found
        """
        connector_class = self.get_connector_class(connector_id)
        return connector_class(config)
    
    # PUBLIC_INTERFACE
    async def list_connectors(self) -> List[Dict[str, any]]:
        """
        List all registered connectors with their metadata.
        
        Returns:
            List[dict]: List of connector information
        """
        connectors = []
        
        for connector_id, connector_class in self._connectors.items():
            metadata = self._metadata.get(connector_id)
            
            connector_info = {
                "id": connector_id,
                "display_name": connector_class.display_name,
                "connector_type": connector_class.connector_type,
                "version": connector_class.version,
                "supports_oauth": connector_class.supports_oauth,
                "supports_webhooks": connector_class.supports_webhooks,
                "required_scopes": connector_class.required_scopes,
                "supported_auth_types": [auth_type.value for auth_type in connector_class.supported_auth_types],
                "supported_resources": [resource.value for resource in connector_class.supported_resources]
            }
            
            if metadata:
                connector_info.update({
                    "description": metadata.description,
                    "icon_url": metadata.icon_url
                })
            
            connectors.append(connector_info)
        
        return connectors
    
    # PUBLIC_INTERFACE
    def is_registered(self, connector_id: str) -> bool:
        """
        Check if a connector is registered.
        
        Args:
            connector_id: Connector identifier
            
        Returns:
            bool: True if connector is registered
        """
        return connector_id in self._connectors
    
    # PUBLIC_INTERFACE
    def get_connector_metadata(self, connector_id: str) -> Optional[ConnectorMetadata]:
        """
        Get metadata for a specific connector.
        
        Args:
            connector_id: Connector identifier
            
        Returns:
            ConnectorMetadata: Connector metadata or None if not found
        """
        return self._metadata.get(connector_id)
    
    # PUBLIC_INTERFACE
    async def initialize(self) -> None:
        """
        Initialize the registry by discovering and registering connectors.
        
        This method should be called during application startup.
        """
        logger.info("Initializing connector registry")
        
        # Import and register all available connectors
        try:
            # Import JIRA connector
            from src.connectors.jira.connector import JiraConnector
            self.register(JiraConnector)
        except ImportError as e:
            logger.warning(f"Failed to import JiraConnector: {e}")
        
        try:
            # Import Confluence connector
            from src.connectors.confluence.connector import ConfluenceConnector
            self.register(ConfluenceConnector)
        except ImportError as e:
            logger.warning(f"Failed to import ConfluenceConnector: {e}")
        
        try:
            # Import Slack connector
            from src.connectors.slack.connector import SlackConnector
            self.register(SlackConnector)
        except ImportError as e:
            logger.warning(f"Failed to import SlackConnector: {e}")
        
        try:
            # Import GitHub connector
            from src.connectors.github.connector import GitHubConnector
            self.register(GitHubConnector)
        except ImportError as e:
            logger.warning(f"Failed to import GitHubConnector: {e}")
        
        try:
            # Import GitLab connector
            from src.connectors.gitlab.connector import GitLabConnector
            self.register(GitLabConnector)
        except ImportError as e:
            logger.warning(f"Failed to import GitLabConnector: {e}")
        
        try:
            # Import ServiceNow connector
            from src.connectors.servicenow.connector import ServiceNowConnector
            self.register(ServiceNowConnector)
        except ImportError as e:
            logger.warning(f"Failed to import ServiceNowConnector: {e}")
        
        registered_count = len(self._connectors)
        logger.info(f"Connector registry initialized with {registered_count} connectors")


# Global connector registry instance
connector_registry = ConnectorRegistry()
