import httpx
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from src.connectors.base import BaseConnector
from src.models.schemas import (
    ConnectorConfig, AuthType, ResourceType, SearchResult
)
from src.core.exceptions import (
    ExternalServiceException, TokenExpiredException, ValidationException
)
from src.core.config import settings


class ConfluenceConnector(BaseConnector):
    """
    Confluence connector for Atlassian Confluence integration.
    
    Supports OAuth 2.0 authentication and provides access to Confluence pages,
    spaces, and content.
    """
    
    id = "confluence"
    display_name = "Confluence"
    connector_type = "atlassian"
    version = "1.0.0"
    
    supports_oauth = True
    supports_webhooks = True
    required_scopes = ["read:confluence-content.all", "write:confluence-content", "read:confluence-space.summary"]
    supported_auth_types = [AuthType.OAUTH2, AuthType.API_KEY]
    supported_resources = [ResourceType.PAGE, ResourceType.SPACE]
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.atlassian.com"
        self.oauth_base_url = "https://auth.atlassian.com"
    
    # PUBLIC_INTERFACE
    async def get_oauth_authorize_url(
        self, 
        tenant_id: str, 
        state: str,
        redirect_uri: str
    ) -> str:
        """
        Get Confluence OAuth authorization URL.
        
        Args:
            tenant_id: Tenant identifier
            state: OAuth state parameter
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            str: Authorization URL
        """
        params = {
            "audience": "api.atlassian.com",
            "client_id": settings.CONFLUENCE_CLIENT_ID,
            "scope": " ".join(self.required_scopes),
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": "code",
            "prompt": "consent"
        }
        
        query_string = urlencode(params)
        return f"{self.oauth_base_url}/authorize?{query_string}"
    
    # PUBLIC_INTERFACE
    async def exchange_code_for_tokens(
        self, 
        tenant_id: str, 
        code: str, 
        state: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Exchange OAuth code for access tokens.
        
        Args:
            tenant_id: Tenant identifier
            code: OAuth authorization code
            state: OAuth state parameter
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            dict: Token information
        """
        token_url = f"{self.oauth_base_url}/oauth/token"
        
        data = {
            "grant_type": "authorization_code",
            "client_id": settings.CONFLUENCE_CLIENT_ID,
            "client_secret": settings.CONFLUENCE_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    token_url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                response.raise_for_status()
                
                token_data = response.json()
                
                # Get accessible resources (Atlassian sites)
                resources = await self._get_accessible_resources(token_data["access_token"])
                
                return {
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "token_type": token_data.get("token_type", "Bearer"),
                    "scope": token_data.get("scope"),
                    "resources": resources
                }
                
            except httpx.RequestError as e:
                raise ExternalServiceException(f"Failed to exchange code for tokens: {e}", "confluence")
            except httpx.HTTPStatusError as e:
                raise ExternalServiceException(f"Token exchange failed: {e.response.text}", "confluence", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def refresh_access_token(
        self, 
        tenant_id: str, 
        refresh_token: str
    ) -> Dict[str, Any]:
        """
        Refresh Confluence access token.
        
        Args:
            tenant_id: Tenant identifier
            refresh_token: OAuth refresh token
            
        Returns:
            dict: New token information
        """
        token_url = f"{self.oauth_base_url}/oauth/token"
        
        data = {
            "grant_type": "refresh_token",
            "client_id": settings.CONFLUENCE_CLIENT_ID,
            "client_secret": settings.CONFLUENCE_CLIENT_SECRET,
            "refresh_token": refresh_token
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    token_url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                response.raise_for_status()
                
                token_data = response.json()
                
                return {
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token", refresh_token),
                    "expires_in": token_data.get("expires_in", 3600),
                    "token_type": token_data.get("token_type", "Bearer"),
                    "scope": token_data.get("scope")
                }
                
            except httpx.RequestError as e:
                raise ExternalServiceException(f"Failed to refresh token: {e}", "confluence")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise TokenExpiredException("confluence")
                raise ExternalServiceException(f"Token refresh failed: {e.response.text}", "confluence", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Validate Confluence credentials.
        
        Args:
            credentials: Credential information
            
        Returns:
            bool: True if credentials are valid
        """
        try:
            headers = await self._get_auth_headers(credentials)
            cloud_id = credentials.get("cloud_id") or credentials.get("resources", [{}])[0].get("id")
            
            if not cloud_id:
                return False
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/user/current",
                    headers=headers,
                    timeout=30
                )
                return response.status_code == 200
                
        except Exception:
            return False
    
    # PUBLIC_INTERFACE
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
        Search Confluence resources.
        
        Args:
            credentials: Authentication credentials
            query: Search query string
            resource_type: Type of resource to search
            filters: Additional search filters
            page: Page number for pagination
            per_page: Number of results per page
            
        Returns:
            tuple: (List of search results, total count)
        """
        if resource_type == ResourceType.PAGE or resource_type is None:
            return await self._search_pages(credentials, query, filters, page, per_page)
        elif resource_type == ResourceType.SPACE:
            return await self._search_spaces(credentials, query, filters, page, per_page)
        else:
            raise ValidationException(f"Unsupported resource type: {resource_type}")
    
    # PUBLIC_INTERFACE
    async def get_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        resource_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific Confluence resource by ID.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to retrieve
            resource_id: Resource identifier
            
        Returns:
            dict: Resource data or None if not found
        """
        headers = await self._get_auth_headers(credentials)
        cloud_id = await self._get_cloud_id(credentials)
        
        try:
            async with httpx.AsyncClient() as client:
                if resource_type == ResourceType.PAGE:
                    response = await client.get(
                        f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/content/{resource_id}",
                        headers=headers,
                        params={"expand": "body.storage,space,version,ancestors"},
                        timeout=30
                    )
                elif resource_type == ResourceType.SPACE:
                    response = await client.get(
                        f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/space/{resource_id}",
                        headers=headers,
                        params={"expand": "description,homepage"},
                        timeout=30
                    )
                else:
                    raise ValidationException(f"Unsupported resource type: {resource_type}")
                
                if response.status_code == 404:
                    return None
                
                response.raise_for_status()
                return response.json()
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to get resource: {e}", "confluence")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("confluence")
            raise ExternalServiceException(f"Failed to get resource: {e.response.text}", "confluence", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def create_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new Confluence resource.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to create
            data: Resource creation data
            
        Returns:
            dict: Created resource data
        """
        headers = await self._get_auth_headers(credentials)
        cloud_id = await self._get_cloud_id(credentials)
        
        try:
            async with httpx.AsyncClient() as client:
                if resource_type == ResourceType.PAGE:
                    # Create Confluence page
                    page_data = {
                        "type": "page",
                        "title": data.get("title"),
                        "space": {"key": data.get("space_key")},
                        "body": {
                            "storage": {
                                "value": data.get("content", ""),
                                "representation": "storage"
                            }
                        }
                    }
                    
                    # Add parent page if specified
                    if data.get("parent_id"):
                        page_data["ancestors"] = [{"id": data.get("parent_id")}]
                    
                    response = await client.post(
                        f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/content",
                        headers=headers,
                        json=page_data,
                        timeout=30
                    )
                else:
                    raise ValidationException(f"Creating {resource_type} is not supported")
                
                response.raise_for_status()
                return response.json()
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to create resource: {e}", "confluence")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("confluence")
            raise ExternalServiceException(f"Failed to create resource: {e.response.text}", "confluence", e.response.status_code)
    
    async def _get_accessible_resources(self, access_token: str) -> List[Dict[str, Any]]:
        """Get accessible Atlassian resources (sites)"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.atlassian.com/oauth/token/accessible-resources",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
    
    async def _get_auth_headers(self, credentials: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers"""
        if credentials.get("access_token"):
            return {
                "Authorization": f"Bearer {credentials['access_token']}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        elif credentials.get("api_key"):
            return {
                "Authorization": f"Basic {credentials['api_key']}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        else:
            raise ValidationException("No valid authentication credentials provided")
    
    async def _get_cloud_id(self, credentials: Dict[str, Any]) -> str:
        """Get Atlassian cloud ID from credentials"""
        cloud_id = credentials.get("cloud_id")
        if not cloud_id:
            resources = credentials.get("resources", [])
            if resources:
                cloud_id = resources[0].get("id")
        
        if not cloud_id:
            raise ValidationException("No Atlassian cloud ID found in credentials")
        
        return cloud_id
    
    async def _search_pages(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search Confluence pages"""
        headers = await self._get_auth_headers(credentials)
        cloud_id = await self._get_cloud_id(credentials)
        
        params = {
            "cql": f'type=page AND text~"{query}"' if query else "type=page",
            "start": (page - 1) * per_page,
            "limit": per_page,
            "expand": "content.space,content.version"
        }
        
        if filters:
            space = filters.get("space")
            if space:
                params["cql"] += f' AND space="{space}"'
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/search",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                pages = data.get("results", [])
                total = data.get("totalSize", 0)
                
                results = []
                for page_data in pages:
                    content = page_data.get("content", {})
                    space = content.get("space", {})
                    
                    results.append(SearchResult(
                        id=content.get("id", ""),
                        title=content.get("title", "No title"),
                        url=f"https://{cloud_id}.atlassian.net/wiki{content.get('_links', {}).get('webui', '')}",
                        type=ResourceType.PAGE,
                        subtitle=f"Space: {space.get('name', 'Unknown')}",
                        metadata={
                            "space_key": space.get("key"),
                            "space_name": space.get("name"),
                            "version": content.get("version", {}).get("number"),
                            "type": content.get("type"),
                            "status": content.get("status")
                        }
                    ))
                
                return results, total
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search pages: {e}", "confluence")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("confluence")
            raise ExternalServiceException(f"Failed to search pages: {e.response.text}", "confluence", e.response.status_code)
    
    async def _search_spaces(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search Confluence spaces"""
        headers = await self._get_auth_headers(credentials)
        cloud_id = await self._get_cloud_id(credentials)
        
        params = {
            "start": (page - 1) * per_page,
            "limit": per_page,
            "expand": "description.plain"
        }
        
        if query:
            params["spaceKey"] = query
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/ex/confluence/{cloud_id}/rest/api/space",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                spaces = data.get("results", [])
                total = data.get("size", len(spaces))
                
                results = []
                for space in spaces:
                    description = space.get("description", {}).get("plain", {}).get("value", "")
                    
                    results.append(SearchResult(
                        id=space.get("key", ""),
                        title=f"{space.get('key', '')}: {space.get('name', 'No name')}",
                        url=f"https://{cloud_id}.atlassian.net/wiki{space.get('_links', {}).get('webui', '')}",
                        type=ResourceType.SPACE,
                        subtitle=f"Type: {space.get('type', 'Unknown')}",
                        metadata={
                            "description": description,
                            "type": space.get("type"),
                            "status": space.get("status")
                        }
                    ))
                
                return results, total
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search spaces: {e}", "confluence")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("confluence")
            raise ExternalServiceException(f"Failed to search spaces: {e.response.text}", "confluence", e.response.status_code)
