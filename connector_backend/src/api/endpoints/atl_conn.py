from fastapi import APIRouter, HTTPException, status, Depends, Query
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
import httpx

from src.core.security import get_current_user
from src.models.schemas import StatusResponse
from loguru import logger

router = APIRouter()

# In-memory store for prototype (do NOT persist). Keys by tenant_id.
_IN_MEMORY_CREDENTIALS: Dict[str, Dict[str, Dict[str, str]]] = {
    # structure:
    # tenant_id: {
    #   "jira": {"domain": "...", "email": "...", "api_token": "..."},
    #   "confluence": {"domain": "...", "email": "...", "api_token": "..."}
    # }
}


class JiraCredentials(BaseModel):
    """JIRA credential payload"""
    domain: str = Field(..., description="Your Atlassian cloud site domain, e.g., example.atlassian.net")
    email: str = Field(..., description="User email for API access")
    api_token: str = Field(..., description="JIRA API token generated from id.atlassian.com")


class ConfluenceCredentials(BaseModel):
    """Confluence credential payload"""
    domain: str = Field(..., description="Your Atlassian cloud site domain, e.g., example.atlassian.net")
    email: str = Field(..., description="User email for API access")
    api_token: str = Field(..., description="Confluence API token generated from id.atlassian.com")


# Helpers

def _store_credentials(tenant_id: str, service: str, data: Dict[str, str]) -> None:
    """Store credentials in memory for the given tenant and service"""
    if tenant_id not in _IN_MEMORY_CREDENTIALS:
        _IN_MEMORY_CREDENTIALS[tenant_id] = {}
    _IN_MEMORY_CREDENTIALS[tenant_id][service] = data


def _get_credentials(tenant_id: str, service: str) -> Optional[Dict[str, str]]:
    """Get stored credentials for the given tenant and service"""
    return _IN_MEMORY_CREDENTIALS.get(tenant_id, {}).get(service)


def _basic_auth_header(email: str, api_token: str) -> Dict[str, str]:
    """Construct Basic auth header for Atlassian"""
    import base64
    token = base64.b64encode(f"{email}:{api_token}".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {token}"}


async def _verify_jira(domain: str, email: str, api_token: str) -> bool:
    """
    Verify JIRA credentials with /rest/api/3/myself on the site-level API.
    """
    headers = {
        **_basic_auth_header(email, api_token),
        "Accept": "application/json"
    }
    url = f"https://{domain}/rest/api/3/myself"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return True
            elif resp.status_code in (401, 403):
                return False
            else:
                logger.warning(f"Unexpected JIRA verify status {resp.status_code}: {resp.text}")
                return False
        except httpx.RequestError as e:
            logger.error(f"JIRA verify request failed: {e}")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to reach JIRA")


async def _verify_confluence(domain: str, email: str, api_token: str) -> bool:
    """
    Verify Confluence credentials with /wiki/rest/api/user/current on the site-level API.
    """
    headers = {
        **_basic_auth_header(email, api_token),
        "Accept": "application/json"
    }
    url = f"https://{domain}/wiki/rest/api/user/current"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return True
            elif resp.status_code in (401, 403):
                return False
            else:
                logger.warning(f"Unexpected Confluence verify status {resp.status_code}: {resp.text}")
                return False
        except httpx.RequestError as e:
            logger.error(f"Confluence verify request failed: {e}")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to reach Confluence")


# Endpoints

# PUBLIC_INTERFACE
@router.post(
    "/connect/jira",
    response_model=StatusResponse,
    summary="Connect JIRA via API token",
    description="Accept JIRA credentials (domain, email, api token), verify with Atlassian, and store them in-memory for the session."
)
async def connect_jira(
    creds: JiraCredentials,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Accept and verify JIRA credentials, then store them in-memory for this tenant.
    - domain: e.g., example.atlassian.net
    - email: Atlassian account email
    - api_token: API token from id.atlassian.com

    Returns:
        StatusResponse with success or error message.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant not found in token")

    is_valid = await _verify_jira(creds.domain, creds.email, creds.api_token)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JIRA credentials")

    _store_credentials(tenant_id, "jira", creds.model_dump())
    return StatusResponse(status="success", message="JIRA connected successfully")


# PUBLIC_INTERFACE
@router.get(
    "/projects/jira",
    summary="List JIRA projects",
    description="After successful JIRA connection, list projects using the stored credentials."
)
async def list_jira_projects(
    q: Optional[str] = Query(None, description="Optional search query to filter projects"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List JIRA projects for the connected account using the site-level API.
    If q is provided, filters by JIRA's project search endpoint 'query' parameter.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant not found in token")

    creds = _get_credentials(tenant_id, "jira")
    if not creds:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JIRA is not connected")

    headers = {
        **_basic_auth_header(creds["email"], creds["api_token"]),
        "Accept": "application/json"
    }

    params = {"expand": "description,lead,insight"}  # safe defaults
    if q:
        # For JIRA Cloud, project search supports 'query' for fuzzy matching
        params["query"] = q

    url = f"https://{creds['domain']}/rest/api/3/project/search"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 401:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired JIRA credentials")
            resp.raise_for_status()
            data = resp.json()
            # Normalize response
            values = data.get("values", data if isinstance(data, list) else [])
            projects: List[Dict[str, Any]] = []
            for p in values:
                projects.append({
                    "id": p.get("id"),
                    "key": p.get("key"),
                    "name": p.get("name"),
                    "projectType": p.get("projectTypeKey"),
                    "lead": (p.get("lead") or {}).get("displayName"),
                    "url": f"https://{creds['domain']}/browse/{p.get('key')}" if p.get("key") else None
                })
            return {"items": projects, "total": len(projects)}
        except httpx.HTTPStatusError as e:
            logger.error(f"JIRA projects failed: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail="Failed to fetch JIRA projects")
        except httpx.RequestError as e:
            logger.error(f"JIRA projects request failed: {e}")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to reach JIRA")


# PUBLIC_INTERFACE
@router.post(
    "/connect/confluence",
    response_model=StatusResponse,
    summary="Connect Confluence via API token",
    description="Accept Confluence credentials (domain, email, api token), verify with Atlassian, and store them in-memory for the session."
)
async def connect_confluence(
    creds: ConfluenceCredentials,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Accept and verify Confluence credentials, then store them in-memory for this tenant.
    - domain: e.g., example.atlassian.net
    - email: Atlassian account email
    - api_token: API token from id.atlassian.com

    Returns:
        StatusResponse with success or error message.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant not found in token")

    is_valid = await _verify_confluence(creds.domain, creds.email, creds.api_token)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Confluence credentials")

    _store_credentials(tenant_id, "confluence", creds.model_dump())
    return StatusResponse(status="success", message="Confluence connected successfully")


# PUBLIC_INTERFACE
@router.get(
    "/spaces/confluence",
    summary="List Confluence spaces",
    description="After successful Confluence connection, list spaces using the stored credentials."
)
async def list_confluence_spaces(
    q: Optional[str] = Query(None, description="Optional filter on spaceKey"),
    limit: int = Query(50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List Confluence spaces for the connected account using the site-level API.
    If q is provided, filters 'spaceKey'.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant not found in token")

    creds = _get_credentials(tenant_id, "confluence")
    if not creds:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Confluence is not connected")

    headers = {
        **_basic_auth_header(creds["email"], creds["api_token"]),
        "Accept": "application/json"
    }

    params = {"limit": limit, "expand": "description.plain"}
    if q:
        params["spaceKey"] = q

    url = f"https://{creds['domain']}/wiki/rest/api/space"
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 401:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired Confluence credentials")
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", data if isinstance(data, list) else [])
            spaces: List[Dict[str, Any]] = []
            for s in results:
                spaces.append({
                    "key": s.get("key"),
                    "name": s.get("name"),
                    "type": s.get("type"),
                    "status": s.get("status"),
                    "description": (s.get("description", {}).get("plain", {}) or {}).get("value"),
                    "url": f"https://{creds['domain']}/wiki{s.get('_links', {}).get('webui', '')}"
                })
            total = data.get("size", len(spaces))
            return {"items": spaces, "total": total}
        except httpx.HTTPStatusError as e:
            logger.error(f"Confluence spaces failed: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail="Failed to fetch Confluence spaces")
        except httpx.RequestError as e:
            logger.error(f"Confluence spaces request failed: {e}")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to reach Confluence")
