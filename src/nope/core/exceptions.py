"""
NOPE Core Exceptions

This module defines custom exceptions used throughout the NOPE platform.
All exceptions inherit from a base NOPEException for consistent error handling.
"""

from typing import Any, Dict, Optional, Union


class NOPEException(Exception):
    """
    Base exception class for all NOPE-specific exceptions.
    
    Provides a consistent interface for error handling with
    support for error codes, details, and context information.
    """
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500
    ) -> None:
        """
        Initialize NOPE exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            details: Additional error context and details
            status_code: HTTP status code for API responses
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.status_code = status_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
            "status_code": self.status_code,
        }
    
    def __str__(self) -> str:
        """String representation of the exception."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


# Configuration Exceptions
class ConfigurationError(NOPEException):
    """Raised when there's an error in application configuration."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        super().__init__(message, details=details, status_code=500, **kwargs)


class MissingConfigurationError(ConfigurationError):
    """Raised when required configuration is missing."""
    pass


class InvalidConfigurationError(ConfigurationError):
    """Raised when configuration values are invalid."""
    pass


# Database Exceptions
class DatabaseError(NOPEException):
    """Base class for database-related exceptions."""
    
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, status_code=500, **kwargs)


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails."""
    pass


class DatabaseQueryError(DatabaseError):
    """Raised when database query execution fails."""
    
    def __init__(
        self,
        message: str,
        query: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if query:
            details["query"] = query
        super().__init__(message, details=details, **kwargs)


class DatabaseMigrationError(DatabaseError):
    """Raised when database migration fails."""
    pass


# Agent Exceptions
class AgentError(NOPEException):
    """Base class for agent-related exceptions."""
    
    def __init__(
        self,
        message: str,
        agent_name: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if agent_name:
            details["agent_name"] = agent_name
        super().__init__(message, details=details, status_code=500, **kwargs)


class AgentInitializationError(AgentError):
    """Raised when agent initialization fails."""
    pass


class AgentExecutionError(AgentError):
    """Raised when agent execution fails."""
    
    def __init__(
        self,
        message: str,
        task_id: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if task_id:
            details["task_id"] = task_id
        super().__init__(message, details=details, **kwargs)


class AgentTimeoutError(AgentError):
    """Raised when agent operation times out."""
    
    def __init__(
        self,
        message: str,
        timeout_duration: Optional[int] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if timeout_duration:
            details["timeout_duration"] = timeout_duration
        super().__init__(message, details=details, status_code=408, **kwargs)


class AgentNotFoundError(AgentError):
    """Raised when requested agent is not found."""
    
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, status_code=404, **kwargs)


# Data Collection Exceptions
class DataCollectionError(NOPEException):
    """Base class for data collection exceptions."""
    
    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if source:
            details["source"] = source
        super().__init__(message, details=details, status_code=500, **kwargs)


class ExternalAPIError(DataCollectionError):
    """Raised when external API calls fail."""
    
    def __init__(
        self,
        message: str,
        api_url: Optional[str] = None,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if api_url:
            details["api_url"] = api_url
        if status_code:
            details["api_status_code"] = status_code
        if response_body:
            details["response_body"] = response_body
        super().__init__(message, details=details, **kwargs)


class RateLimitExceededError(ExternalAPIError):
    """Raised when API rate limits are exceeded."""
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, details=details, status_code=429, **kwargs)


class DataValidationError(DataCollectionError):
    """Raised when collected data fails validation."""
    
    def __init__(
        self,
        message: str,
        validation_errors: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if validation_errors:
            details["validation_errors"] = validation_errors
        super().__init__(message, details=details, status_code=400, **kwargs)


# Machine Learning Exceptions
class MLError(NOPEException):
    """Base class for machine learning exceptions."""
    
    def __init__(
        self,
        message: str,
        model_name: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if model_name:
            details["model_name"] = model_name
        super().__init__(message, details=details, status_code=500, **kwargs)


class ModelTrainingError(MLError):
    """Raised when model training fails."""
    
    def __init__(
        self,
        message: str,
        epoch: Optional[int] = None,
        loss: Optional[float] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if epoch is not None:
            details["epoch"] = epoch
        if loss is not None:
            details["loss"] = loss
        super().__init__(message, details=details, **kwargs)


class ModelLoadError(MLError):
    """Raised when model loading fails."""
    
    def __init__(
        self,
        message: str,
        model_path: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if model_path:
            details["model_path"] = model_path
        super().__init__(message, details=details, **kwargs)


class ModelPredictionError(MLError):
    """Raised when model prediction fails."""
    
    def __init__(
        self,
        message: str,
        input_shape: Optional[tuple] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if input_shape:
            details["input_shape"] = input_shape
        super().__init__(message, details=details, **kwargs)


class EnsembleError(MLError):
    """Raised when ensemble model operations fail."""
    pass


# Correlation Exceptions
class CorrelationError(NOPEException):
    """Base class for correlation engine exceptions."""
    
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, status_code=500, **kwargs)


class PatternMatchingError(CorrelationError):
    """Raised when pattern matching fails."""
    
    def __init__(
        self,
        message: str,
        pattern: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if pattern:
            details["pattern"] = pattern
        super().__init__(message, details=details, **kwargs)


class ThreatCorrelationError(CorrelationError):
    """Raised when threat correlation fails."""
    
    def __init__(
        self,
        message: str,
        cve_id: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if cve_id:
            details["cve_id"] = cve_id
        super().__init__(message, details=details, **kwargs)


# API Exceptions
class APIError(NOPEException):
    """Base class for API-related exceptions."""
    pass


class ValidationError(APIError):
    """Raised when request validation fails."""
    
    def __init__(
        self,
        message: str,
        field_errors: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if field_errors:
            details["field_errors"] = field_errors
        super().__init__(message, details=details, status_code=400, **kwargs)


class AuthenticationError(APIError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs) -> None:
        super().__init__(message, status_code=401, **kwargs)


class AuthorizationError(APIError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Access denied", **kwargs) -> None:
        super().__init__(message, status_code=403, **kwargs)


class NotFoundError(APIError):
    """Raised when requested resource is not found."""
    
    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = str(resource_id)
        super().__init__(message, details=details, status_code=404, **kwargs)


class ConflictError(APIError):
    """Raised when request conflicts with current state."""
    
    def __init__(self, message: str, **kwargs) -> None:
        super().__init__(message, status_code=409, **kwargs)


class TooManyRequestsError(APIError):
    """Raised when rate limits are exceeded."""
    
    def __init__(
        self,
        message: str = "Too many requests",
        retry_after: Optional[int] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, details=details, status_code=429, **kwargs)


# Notification Exceptions
class NotificationError(NOPEException):
    """Base class for notification exceptions."""
    
    def __init__(
        self,
        message: str,
        notification_type: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if notification_type:
            details["notification_type"] = notification_type
        super().__init__(message, details=details, status_code=500, **kwargs)


class EmailDeliveryError(NotificationError):
    """Raised when email delivery fails."""
    
    def __init__(
        self,
        message: str,
        recipient: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if recipient:
            details["recipient"] = recipient
        super().__init__(message, notification_type="email", details=details, **kwargs)


class SlackDeliveryError(NotificationError):
    """Raised when Slack message delivery fails."""
    
    def __init__(
        self,
        message: str,
        channel: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if channel:
            details["channel"] = channel
        super().__init__(message, notification_type="slack", details=details, **kwargs)


class WebhookDeliveryError(NotificationError):
    """Raised when webhook delivery fails."""
    
    def __init__(
        self,
        message: str,
        webhook_url: Optional[str] = None,
        **kwargs
    ) -> None:
        details = kwargs.pop("details", {})
        if webhook_url:
            details["webhook_url"] = webhook_url
        super().__init__(message, notification_type="webhook", details=details, **kwargs)