from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError
from loguru import logger
import traceback



class ConnectorException(Exception):
    """Base exception for connector-related errors"""
    
    def __init__(self, message: str, code: str = "CONNECTOR_ERROR", details: dict = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationException(ConnectorException):
    """Exception for authentication-related errors"""
    
    def __init__(self, message: str = "Authentication failed", details: dict = None):
        super().__init__(message, "AUTHENTICATION_ERROR", details)


class AuthorizationException(ConnectorException):
    """Exception for authorization-related errors"""
    
    def __init__(self, message: str = "Access denied", details: dict = None):
        super().__init__(message, "AUTHORIZATION_ERROR", details)


class ConnectorNotFoundException(ConnectorException):
    """Exception when a connector is not found"""
    
    def __init__(self, connector_id: str):
        super().__init__(
            f"Connector '{connector_id}' not found",
            "CONNECTOR_NOT_FOUND",
            {"connector_id": connector_id}
        )


class ConnectorConfigurationException(ConnectorException):
    """Exception for connector configuration errors"""
    
    def __init__(self, message: str, connector_id: str = None):
        super().__init__(
            message,
            "CONNECTOR_CONFIGURATION_ERROR",
            {"connector_id": connector_id} if connector_id else {}
        )


class TokenExpiredException(ConnectorException):
    """Exception when OAuth token is expired"""
    
    def __init__(self, connector_id: str):
        super().__init__(
            f"Token expired for connector '{connector_id}'",
            "TOKEN_EXPIRED",
            {"connector_id": connector_id}
        )


class RateLimitException(ConnectorException):
    """Exception when rate limit is exceeded"""
    
    def __init__(self, retry_after: int = None):
        super().__init__(
            "Rate limit exceeded",
            "RATE_LIMITED",
            {"retry_after": retry_after} if retry_after else {}
        )


class WorkflowException(ConnectorException):
    """Exception for workflow-related errors"""
    
    def __init__(self, message: str, workflow_id: str = None):
        super().__init__(
            message,
            "WORKFLOW_ERROR",
            {"workflow_id": workflow_id} if workflow_id else {}
        )


class ValidationException(ConnectorException):
    """Exception for validation errors"""
    
    def __init__(self, message: str, field: str = None):
        super().__init__(
            message,
            "VALIDATION_ERROR",
            {"field": field} if field else {}
        )


class ExternalServiceException(ConnectorException):
    """Exception for external service integration errors"""
    
    def __init__(self, message: str, service: str, status_code: int = None):
        super().__init__(
            message,
            "EXTERNAL_SERVICE_ERROR",
            {"service": service, "status_code": status_code}
        )


# PUBLIC_INTERFACE
def setup_exception_handlers(app: FastAPI) -> None:
    """
    Setup global exception handlers for the FastAPI application.
    
    Args:
        app: FastAPI application instance
    """
    
    @app.exception_handler(ConnectorException)
    async def connector_exception_handler(request: Request, exc: ConnectorException):
        """Handle custom connector exceptions"""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.error(
            f"Connector exception: {exc.message}",
            extra={
                "request_id": request_id,
                "error_code": exc.code,
                "details": exc.details,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        status_code_map = {
            "AUTHENTICATION_ERROR": status.HTTP_401_UNAUTHORIZED,
            "AUTHORIZATION_ERROR": status.HTTP_403_FORBIDDEN,
            "CONNECTOR_NOT_FOUND": status.HTTP_404_NOT_FOUND,
            "CONNECTOR_CONFIGURATION_ERROR": status.HTTP_400_BAD_REQUEST,
            "TOKEN_EXPIRED": status.HTTP_401_UNAUTHORIZED,
            "RATE_LIMITED": status.HTTP_429_TOO_MANY_REQUESTS,
            "WORKFLOW_ERROR": status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "EXTERNAL_SERVICE_ERROR": status.HTTP_502_BAD_GATEWAY,
        }
        
        status_code = status_code_map.get(exc.code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        response_data = {
            "status": "error",
            "code": exc.code,
            "message": exc.message,
            "request_id": request_id
        }
        
        if exc.details:
            response_data["details"] = exc.details
        
        # Add retry_after header for rate limiting
        headers = {}
        if exc.code == "RATE_LIMITED" and exc.details.get("retry_after"):
            headers["Retry-After"] = str(exc.details["retry_after"])
        
        return JSONResponse(
            status_code=status_code,
            content=response_data,
            headers=headers
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Handle HTTP exceptions"""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.warning(
            f"HTTP exception: {exc.detail}",
            extra={
                "request_id": request_id,
                "status_code": exc.status_code,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": "error",
                "code": "HTTP_ERROR",
                "message": exc.detail,
                "request_id": request_id
            }
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle request validation errors"""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.warning(
            f"Validation error: {exc.errors()}",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "errors": exc.errors()
            }
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "error",
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "request_id": request_id,
                "details": {
                    "errors": exc.errors()
                }
            }
        )
    
    @app.exception_handler(ValidationError)
    async def pydantic_validation_exception_handler(request: Request, exc: ValidationError):
        """Handle Pydantic validation errors"""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.warning(
            f"Pydantic validation error: {exc.errors()}",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "errors": exc.errors()
            }
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "error",
                "code": "VALIDATION_ERROR",
                "message": "Data validation failed",
                "request_id": request_id,
                "details": {
                    "errors": exc.errors()
                }
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions"""
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        logger.error(
            f"Unexpected error: {str(exc)}",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "traceback": traceback.format_exc()
            }
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "request_id": request_id
            }
        )
