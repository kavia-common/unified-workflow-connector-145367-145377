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


class SlackConnector(BaseConnector):
    """
    Slack connector for Slack workspace integration.
    
    Supports OAuth 2.0 authentication and provides access to Slack channels,
    messages, and users.
    """
    
    id = "slack"
    display_name = "Slack"
    connector_type = "communication"
    version = "1.0.0"
    
    supports_oauth = True
    supports_webhooks = True
    required_scopes = ["channels:read", "chat:write", "users:read", "channels:history"]
    supported_auth_types = [AuthType.OAUTH2]
    supported_resources = [ResourceType.CHANNEL, ResourceType.USER]
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = "https://slack.com/api"
        self.oauth_base_url = "https://slack.com/oauth/v2"
    
    # PUBLIC_INTERFACE
    async def get_oauth_authorize_url(
        self, 
        tenant_id: str, 
        state: str,
        redirect_uri: str
    ) -> str:
        """
        Get Slack OAuth authorization URL.
        
        Args:
            tenant_id: Tenant identifier
            state: OAuth state parameter
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            str: Authorization URL
        """
        params = {
            "client_id": settings.SLACK_CLIENT_ID,
            "scope": " ".join(self.required_scopes),
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": "code"
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
        token_url = f"{self.oauth_base_url}/access"
        
        data = {
            "client_id": settings.SLACK_CLIENT_ID,
            "client_secret": settings.SLACK_CLIENT_SECRET,
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
                
                if not token_data.get("ok"):
                    raise ExternalServiceException(f"Slack OAuth error: {token_data.get('error')}", "slack")
                
                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "Bearer"),
                    "scope": token_data.get("scope"),
                    "team": token_data.get("team", {}),
                    "authed_user": token_data.get("authed_user", {})
                }
                
            except httpx.RequestError as e:
                raise ExternalServiceException(f"Failed to exchange code for tokens: {e}", "slack")
            except httpx.HTTPStatusError as e:
                raise ExternalServiceException(f"Token exchange failed: {e.response.text}", "slack", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def refresh_access_token(
        self, 
        tenant_id: str, 
        refresh_token: str
    ) -> Dict[str, Any]:
        """
        Slack doesn't support token refresh, tokens are long-lived.
        
        Args:
            tenant_id: Tenant identifier
            refresh_token: OAuth refresh token
            
        Returns:
            dict: Token information (unchanged)
        """
        raise NotImplementedError("Slack tokens are long-lived and don't require refresh")
    
    # PUBLIC_INTERFACE
    async def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Validate Slack credentials.
        
        Args:
            credentials: Credential information
            
        Returns:
            bool: True if credentials are valid
        """
        try:
            headers = await self._get_auth_headers(credentials)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth.test",
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("ok", False)
                
                return False
                
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
        Search Slack resources.
        
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
        if resource_type == ResourceType.CHANNEL or resource_type is None:
            return await self._search_channels(credentials, query, filters, page, per_page)
        elif resource_type == ResourceType.USER:
            return await self._search_users(credentials, query, filters, page, per_page)
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
        Get a specific Slack resource by ID.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to retrieve
            resource_id: Resource identifier
            
        Returns:
            dict: Resource data or None if not found
        """
        headers = await self._get_auth_headers(credentials)
        
        try:
            async with httpx.AsyncClient() as client:
                if resource_type == ResourceType.CHANNEL:
                    response = await client.get(
                        f"{self.base_url}/conversations.info",
                        headers=headers,
                        params={"channel": resource_id},
                        timeout=30
                    )
                elif resource_type == ResourceType.USER:
                    response = await client.get(
                        f"{self.base_url}/users.info",
                        headers=headers,
                        params={"user": resource_id},
                        timeout=30
                    )
                else:
                    raise ValidationException(f"Unsupported resource type: {resource_type}")
                
                response.raise_for_status()
                data = response.json()
                
                if not data.get("ok"):
                    if data.get("error") == "channel_not_found" or data.get("error") == "user_not_found":
                        return None
                    raise ExternalServiceException(f"Slack API error: {data.get('error')}", "slack")
                
                return data.get("channel") or data.get("user")
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to get resource: {e}", "slack")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("slack")
            raise ExternalServiceException(f"Failed to get resource: {e.response.text}", "slack", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def create_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new Slack resource.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to create
            data: Resource creation data
            
        Returns:
            dict: Created resource data
        """
        headers = await self._get_auth_headers(credentials)
        
        try:
            async with httpx.AsyncClient() as client:
                if resource_type == ResourceType.CHANNEL:
                    # Create Slack channel
                    response = await client.post(
                        f"{self.base_url}/conversations.create",
                        headers=headers,
                        json={
                            "name": data.get("name"),
                            "is_private": data.get("is_private", False)
                        },
                        timeout=30
                    )
                else:
                    raise ValidationException(f"Creating {resource_type} is not supported")
                
                response.raise_for_status()
                response_data = response.json()
                
                if not response_data.get("ok"):
                    raise ExternalServiceException(f"Slack API error: {response_data.get('error')}", "slack")
                
                return response_data.get("channel", {})
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to create resource: {e}", "slack")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("slack")
            raise ExternalServiceException(f"Failed to create resource: {e.response.text}", "slack", e.response.status_code)
    
    async def _get_auth_headers(self, credentials: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers"""
        access_token = credentials.get("access_token")
        if not access_token:
            raise ValidationException("No access token found in credentials")
        
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
    
    async def _search_channels(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search Slack channels"""
        headers = await self._get_auth_headers(credentials)
        
        params = {
            "types": "public_channel,private_channel",
            "limit": per_page
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/conversations.list",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                
                if not data.get("ok"):
                    raise ExternalServiceException(f"Slack API error: {data.get('error')}", "slack")
                
                channels = data.get("channels", [])
                
                # Filter channels by query if provided
                if query:
                    filtered_channels = [
                        channel for channel in channels
                        if query.lower() in channel.get("name", "").lower() or 
                           query.lower() in channel.get("purpose", {}).get("value", "").lower()
                    ]
                else:
                    filtered_channels = channels
                
                results = []
                for channel in filtered_channels:
                    results.append(SearchResult(
                        id=channel.get("id", ""),
                        title=f"#{channel.get('name', 'Unknown')}",
                        url=None,  # Slack doesn't provide direct URLs in API
                        type=ResourceType.CHANNEL,
                        subtitle=channel.get("purpose", {}).get("value", "No description"),
                        metadata={
                            "is_private": channel.get("is_private", False),
                            "is_archived": channel.get("is_archived", False),
                            "num_members": channel.get("num_members", 0),
                            "created": channel.get("created")
                        }
                    ))
                
                return results, len(filtered_channels)
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search channels: {e}", "slack")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("slack")
            raise ExternalServiceException(f"Failed to search channels: {e.response.text}", "slack", e.response.status_code)
    
    async def _search_users(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search Slack users"""
        headers = await self._get_auth_headers(credentials)
        
        params = {
            "limit": per_page
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/users.list",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                
                if not data.get("ok"):
                    raise ExternalServiceException(f"Slack API error: {data.get('error')}", "slack")
                
                users = data.get("members", [])
                
                # Filter users by query if provided
                if query:
                    filtered_users = [
                        user for user in users
                        if query.lower() in user.get("name", "").lower() or 
                           query.lower() in user.get("real_name", "").lower() or
                           query.lower() in user.get("profile", {}).get("email", "").lower()
                    ]
                else:
                    filtered_users = users
                
                results = []
                for user in filtered_users:
                    profile = user.get("profile", {})
                    results.append(SearchResult(
                        id=user.get("id", ""),
                        title=f"@{user.get('name', 'Unknown')}",
                        url=None,
                        type=ResourceType.USER,
                        subtitle=profile.get("real_name", "No real name"),
                        metadata={
                            "email": profile.get("email"),
                            "is_bot": user.get("is_bot", False),
                            "is_admin": user.get("is_admin", False),
                            "is_restricted": user.get("is_restricted", False),
                            "deleted": user.get("deleted", False)
                        }
                    ))
                
                return results, len(filtered_users)
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search users: {e}", "slack")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("slack")
            raise ExternalServiceException(f"Failed to search users: {e.response.text}", "slack", e.response.status_code)
