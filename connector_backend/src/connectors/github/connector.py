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


class GitHubConnector(BaseConnector):
    """
    GitHub connector for GitHub repository integration.
    
    Supports OAuth 2.0 authentication and provides access to GitHub repositories,
    issues, and pull requests.
    """
    
    id = "github"
    display_name = "GitHub"
    connector_type = "version_control"
    version = "1.0.0"
    
    supports_oauth = True
    supports_webhooks = True
    required_scopes = ["repo", "read:user"]
    supported_auth_types = [AuthType.OAUTH2]
    supported_resources = [ResourceType.REPOSITORY, ResourceType.ISSUE]
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = "https://api.github.com"
        self.oauth_base_url = "https://github.com/login/oauth"
    
    # PUBLIC_INTERFACE
    async def get_oauth_authorize_url(
        self, 
        tenant_id: str, 
        state: str,
        redirect_uri: str
    ) -> str:
        """
        Get GitHub OAuth authorization URL.
        
        Args:
            tenant_id: Tenant identifier
            state: OAuth state parameter
            redirect_uri: OAuth callback redirect URI
            
        Returns:
            str: Authorization URL
        """
        params = {
            "client_id": settings.GITHUB_CLIENT_ID,
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
        token_url = f"{self.oauth_base_url}/access_token"
        
        data = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    token_url,
                    data=data,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                )
                response.raise_for_status()
                
                token_data = response.json()
                
                if "error" in token_data:
                    raise ExternalServiceException(f"GitHub OAuth error: {token_data.get('error_description')}", "github")
                
                return {
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "bearer"),
                    "scope": token_data.get("scope")
                }
                
            except httpx.RequestError as e:
                raise ExternalServiceException(f"Failed to exchange code for tokens: {e}", "github")
            except httpx.HTTPStatusError as e:
                raise ExternalServiceException(f"Token exchange failed: {e.response.text}", "github", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def refresh_access_token(
        self, 
        tenant_id: str, 
        refresh_token: str
    ) -> Dict[str, Any]:
        """
        GitHub doesn't support token refresh, tokens are long-lived.
        
        Args:
            tenant_id: Tenant identifier
            refresh_token: OAuth refresh token
            
        Returns:
            dict: Token information (unchanged)
        """
        raise NotImplementedError("GitHub tokens are long-lived and don't require refresh")
    
    # PUBLIC_INTERFACE
    async def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Validate GitHub credentials.
        
        Args:
            credentials: Credential information
            
        Returns:
            bool: True if credentials are valid
        """
        try:
            headers = await self._get_auth_headers(credentials)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/user",
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
        Search GitHub resources.
        
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
        if resource_type == ResourceType.REPOSITORY or resource_type is None:
            return await self._search_repositories(credentials, query, filters, page, per_page)
        elif resource_type == ResourceType.ISSUE:
            return await self._search_issues(credentials, query, filters, page, per_page)
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
        Get a specific GitHub resource by ID.
        
        Args:
            credentials: Authentication credentials
            resource_type: Type of resource to retrieve
            resource_id: Resource identifier (owner/repo format for repositories)
            
        Returns:
            dict: Resource data or None if not found
        """
        headers = await self._get_auth_headers(credentials)
        
        try:
            async with httpx.AsyncClient() as client:
                if resource_type == ResourceType.REPOSITORY:
                    response = await client.get(
                        f"{self.base_url}/repos/{resource_id}",
                        headers=headers,
                        timeout=30
                    )
                elif resource_type == ResourceType.ISSUE:
                    # resource_id should be in format "owner/repo/issue_number"
                    parts = resource_id.split("/")
                    if len(parts) >= 3:
                        owner, repo, issue_number = parts[0], parts[1], parts[2]
                        response = await client.get(
                            f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}",
                            headers=headers,
                            timeout=30
                        )
                    else:
                        raise ValidationException("Invalid issue resource ID format")
                else:
                    raise ValidationException(f"Unsupported resource type: {resource_type}")
                
                if response.status_code == 404:
                    return None
                
                response.raise_for_status()
                return response.json()
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to get resource: {e}", "github")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("github")
            raise ExternalServiceException(f"Failed to get resource: {e.response.text}", "github", e.response.status_code)
    
    # PUBLIC_INTERFACE
    async def create_resource(
        self, 
        credentials: Dict[str, Any],
        resource_type: ResourceType,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new GitHub resource.
        
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
                if resource_type == ResourceType.REPOSITORY:
                    # Create GitHub repository
                    repo_data = {
                        "name": data.get("name"),
                        "description": data.get("description", ""),
                        "private": data.get("private", False),
                        "auto_init": data.get("auto_init", True)
                    }
                    
                    response = await client.post(
                        f"{self.base_url}/user/repos",
                        headers=headers,
                        json=repo_data,
                        timeout=30
                    )
                elif resource_type == ResourceType.ISSUE:
                    # Create GitHub issue
                    repo = data.get("repository")  # Should be in "owner/repo" format
                    if not repo:
                        raise ValidationException("Repository is required for issue creation")
                    
                    issue_data = {
                        "title": data.get("title"),
                        "body": data.get("body", ""),
                        "labels": data.get("labels", []),
                        "assignees": data.get("assignees", [])
                    }
                    
                    response = await client.post(
                        f"{self.base_url}/repos/{repo}/issues",
                        headers=headers,
                        json=issue_data,
                        timeout=30
                    )
                else:
                    raise ValidationException(f"Creating {resource_type} is not supported")
                
                response.raise_for_status()
                return response.json()
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to create resource: {e}", "github")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("github")
            raise ExternalServiceException(f"Failed to create resource: {e.response.text}", "github", e.response.status_code)
    
    async def _get_auth_headers(self, credentials: Dict[str, Any]) -> Dict[str, str]:
        """Get authentication headers"""
        access_token = credentials.get("access_token")
        if not access_token:
            raise ValidationException("No access token found in credentials")
        
        return {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Unified-Workflow-Connector/1.0"
        }
    
    async def _search_repositories(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search GitHub repositories"""
        headers = await self._get_auth_headers(credentials)
        
        # Build search query
        search_query = query if query else "stars:>0"
        
        if filters:
            language = filters.get("language")
            if language:
                search_query += f" language:{language}"
            
            user = filters.get("user")
            if user:
                search_query += f" user:{user}"
        
        params = {
            "q": search_query,
            "sort": "stars",
            "order": "desc",
            "page": page,
            "per_page": per_page
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/search/repositories",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                repositories = data.get("items", [])
                total_count = data.get("total_count", 0)
                
                results = []
                for repo in repositories:
                    results.append(SearchResult(
                        id=repo.get("full_name", ""),
                        title=repo.get("full_name", "Unknown"),
                        url=repo.get("html_url"),
                        type=ResourceType.REPOSITORY,
                        subtitle=repo.get("description", "No description"),
                        metadata={
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count", 0),
                            "forks": repo.get("forks_count", 0),
                            "private": repo.get("private", False),
                            "updated_at": repo.get("updated_at")
                        }
                    ))
                
                return results, total_count
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search repositories: {e}", "github")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("github")
            raise ExternalServiceException(f"Failed to search repositories: {e.response.text}", "github", e.response.status_code)
    
    async def _search_issues(
        self, 
        credentials: Dict[str, Any], 
        query: str, 
        filters: Optional[Dict[str, Any]], 
        page: int, 
        per_page: int
    ) -> Tuple[List[SearchResult], int]:
        """Search GitHub issues"""
        headers = await self._get_auth_headers(credentials)
        
        # Build search query
        search_query = f"{query} type:issue" if query else "type:issue"
        
        if filters:
            repo = filters.get("repository")
            if repo:
                search_query += f" repo:{repo}"
            
            state = filters.get("state")
            if state:
                search_query += f" state:{state}"
            
            label = filters.get("label")
            if label:
                search_query += f" label:{label}"
        
        params = {
            "q": search_query,
            "sort": "updated",
            "order": "desc",
            "page": page,
            "per_page": per_page
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/search/issues",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                issues = data.get("items", [])
                total_count = data.get("total_count", 0)
                
                results = []
                for issue in issues:
                    # Extract repository name from URL
                    repo_url = issue.get("repository_url", "")
                    repo_name = repo_url.split("/")[-2:] if repo_url else ["", ""]
                    repo_full_name = "/".join(repo_name) if len(repo_name) == 2 else "Unknown"
                    
                    results.append(SearchResult(
                        id=f"{repo_full_name}/{issue.get('number', '')}",
                        title=f"#{issue.get('number', '')}: {issue.get('title', 'No title')}",
                        url=issue.get("html_url"),
                        type=ResourceType.ISSUE,
                        subtitle=f"Repository: {repo_full_name}",
                        metadata={
                            "state": issue.get("state"),
                            "repository": repo_full_name,
                            "labels": [label.get("name") for label in issue.get("labels", [])],
                            "assignee": issue.get("assignee", {}).get("login") if issue.get("assignee") else None,
                            "created_at": issue.get("created_at"),
                            "updated_at": issue.get("updated_at")
                        }
                    ))
                
                return results, total_count
                
        except httpx.RequestError as e:
            raise ExternalServiceException(f"Failed to search issues: {e}", "github")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise TokenExpiredException("github")
            raise ExternalServiceException(f"Failed to search issues: {e.response.text}", "github", e.response.status_code)
