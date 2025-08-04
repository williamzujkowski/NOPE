"""
NOPE Core Configuration

This module provides configuration management for the NOPE platform,
including environment variable handling, validation, and default values.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseSettings, Field, validator
from pydantic.networks import AnyHttpUrl, PostgresDsn, RedisDsn


class Settings(BaseSettings):
    """
    NOPE application settings loaded from environment variables.
    
    Uses Pydantic BaseSettings for automatic environment variable loading
    and validation with type hints.
    """
    
    # Application Settings
    app_name: str = Field(default="NOPE", env="APP_NAME")
    version: str = Field(default="0.1.0", env="VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    secret_key: str = Field(..., env="SECRET_KEY")
    
    # API Server Settings
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=4, env="API_WORKERS")
    api_reload: bool = Field(default=False, env="API_RELOAD")
    
    # Database Settings
    database_url: PostgresDsn = Field(..., env="DATABASE_URL")
    database_pool_size: int = Field(default=20, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=30, env="DATABASE_MAX_OVERFLOW")
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Redis Settings
    redis_url: RedisDsn = Field(..., env="REDIS_URL")
    redis_pool_size: int = Field(default=10, env="REDIS_POOL_SIZE")
    redis_decode_responses: bool = Field(default=True, env="REDIS_DECODE_RESPONSES")
    
    # Celery Settings
    celery_broker_url: RedisDsn = Field(..., env="CELERY_BROKER_URL")
    celery_result_backend: RedisDsn = Field(..., env="CELERY_RESULT_BACKEND")
    celery_worker_concurrency: int = Field(default=4, env="CELERY_WORKER_CONCURRENCY")
    celery_task_always_eager: bool = Field(default=False, env="CELERY_TASK_ALWAYS_EAGER")
    
    # Machine Learning Settings
    model_path: Path = Field(default=Path("./models"), env="MODEL_PATH")
    ensemble_strategy: str = Field(default="weighted_voting", env="ENSEMBLE_STRATEGY")
    prediction_threshold: float = Field(default=0.7, env="PREDICTION_THRESHOLD")
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        env="EMBEDDING_MODEL"
    )
    max_features: int = Field(default=10000, env="MAX_FEATURES")
    
    # Agent Configuration
    agent_pool_size: int = Field(default=10, env="AGENT_POOL_SIZE")
    collection_interval: int = Field(default=3600, env="COLLECTION_INTERVAL")  # 1 hour
    analysis_batch_size: int = Field(default=1000, env="ANALYSIS_BATCH_SIZE")
    max_retries: int = Field(default=3, env="MAX_RETRIES")
    agent_timeout: int = Field(default=300, env="AGENT_TIMEOUT")  # 5 minutes
    
    # External API Keys
    nvd_api_key: Optional[str] = Field(default=None, env="NVD_API_KEY")
    github_token: Optional[str] = Field(default=None, env="GITHUB_TOKEN")
    twitter_api_key: Optional[str] = Field(default=None, env="TWITTER_API_KEY")
    misp_url: Optional[AnyHttpUrl] = Field(default=None, env="MISP_URL")
    misp_api_key: Optional[str] = Field(default=None, env="MISP_API_KEY")
    otx_api_key: Optional[str] = Field(default=None, env="OTX_API_KEY")
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    
    # SMTP Settings
    smtp_server: Optional[str] = Field(default=None, env="SMTP_SERVER")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, env="SMTP_USER")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_tls: bool = Field(default=True, env="SMTP_TLS")
    
    # Slack Settings
    slack_webhook_url: Optional[AnyHttpUrl] = Field(default=None, env="SLACK_WEBHOOK_URL")
    slack_channel: str = Field(default="#security-alerts", env="SLACK_CHANNEL")
    
    # Webhook Settings
    webhook_urls: List[AnyHttpUrl] = Field(default_factory=list, env="WEBHOOK_URLS")
    webhook_tokens: List[str] = Field(default_factory=list, env="WEBHOOK_TOKENS")
    
    # Monitoring Settings
    prometheus_host: str = Field(default="localhost", env="PROMETHEUS_HOST")
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    grafana_host: str = Field(default="localhost", env="GRAFANA_HOST")
    grafana_port: int = Field(default=3000, env="GRAFANA_PORT")
    grafana_admin_password: str = Field(default="admin", env="GRAFANA_ADMIN_PASSWORD")
    
    # Logging Settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file: Optional[Path] = Field(default=None, env="LOG_FILE")
    log_max_size: str = Field(default="100MB", env="LOG_MAX_SIZE")
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Security Settings
    encryption_key: str = Field(..., env="ENCRYPTION_KEY")
    jwt_secret: str = Field(..., env="JWT_SECRET")
    jwt_expiration: int = Field(default=86400, env="JWT_EXPIRATION")  # 24 hours
    bcrypt_rounds: int = Field(default=12, env="BCRYPT_ROUNDS")
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    rate_limit_burst: int = Field(default=10, env="RATE_LIMIT_BURST")
    
    # Caching
    cache_ttl: int = Field(default=3600, env="CACHE_TTL")  # 1 hour
    prediction_cache_ttl: int = Field(default=7200, env="PREDICTION_CACHE_TTL")  # 2 hours
    
    # Feature Flags
    enable_real_time_prediction: bool = Field(default=True, env="ENABLE_REAL_TIME_PREDICTION")
    enable_twitter_monitoring: bool = Field(default=False, env="ENABLE_TWITTER_MONITORING")
    enable_advanced_correlation: bool = Field(default=True, env="ENABLE_ADVANCED_CORRELATION")
    enable_auto_retraining: bool = Field(default=True, env="ENABLE_AUTO_RETRAINING")
    enable_vulnerability_scoring: bool = Field(default=True, env="ENABLE_VULNERABILITY_SCORING")
    
    # Testing Settings
    pytest_timeout: int = Field(default=300, env="PYTEST_TIMEOUT")
    coverage_threshold: int = Field(default=80, env="COVERAGE_THRESHOLD")
    mock_external_apis: bool = Field(default=False, env="MOCK_EXTERNAL_APIS")
    
    # Frontend Settings
    eleventy_env: str = Field(default="development", env="ELEVENTY_ENV")
    site_url: AnyHttpUrl = Field(default="http://localhost:8080", env="SITE_URL")
    api_base_url: AnyHttpUrl = Field(default="http://localhost:8000/api/v1", env="API_BASE_URL")
    
    @validator("environment")
    def validate_environment(cls, v: str) -> str:
        """Validate environment setting."""
        allowed_envs = ["development", "staging", "production", "test"]
        if v not in allowed_envs:
            raise ValueError(f"Environment must be one of: {allowed_envs}")
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level setting."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()
    
    @validator("ensemble_strategy")
    def validate_ensemble_strategy(cls, v: str) -> str:
        """Validate ensemble strategy setting."""
        allowed_strategies = ["voting", "weighted_voting", "stacking", "blending"]
        if v not in allowed_strategies:
            raise ValueError(f"Ensemble strategy must be one of: {allowed_strategies}")
        return v
    
    @validator("prediction_threshold")
    def validate_prediction_threshold(cls, v: float) -> float:
        """Validate prediction threshold is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Prediction threshold must be between 0.0 and 1.0")
        return v
    
    @validator("model_path")
    def validate_model_path(cls, v: Path) -> Path:
        """Ensure model path exists or can be created."""
        if not v.exists():
            v.mkdir(parents=True, exist_ok=True)
        return v
    
    @validator("webhook_urls", pre=True)
    def parse_webhook_urls(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse webhook URLs from comma-separated string or list."""
        if isinstance(v, str):
            return [url.strip() for url in v.split(",") if url.strip()]
        return v or []
    
    @validator("webhook_tokens", pre=True)
    def parse_webhook_tokens(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse webhook tokens from comma-separated string or list."""
        if isinstance(v, str):
            return [token.strip() for token in v.split(",") if token.strip()]
        return v or []
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"
    
    @property
    def is_testing(self) -> bool:
        """Check if running in test mode."""
        return self.environment == "test"
    
    @property
    def database_config(self) -> Dict[str, Any]:
        """Get database configuration dictionary."""
        return {
            "url": str(self.database_url),
            "pool_size": self.database_pool_size,
            "max_overflow": self.database_max_overflow,
            "echo": self.database_echo,
        }
    
    @property
    def redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration dictionary."""
        return {
            "url": str(self.redis_url),
            "max_connections": self.redis_pool_size,
            "decode_responses": self.redis_decode_responses,
        }
    
    @property
    def celery_config(self) -> Dict[str, Any]:
        """Get Celery configuration dictionary."""
        return {
            "broker_url": str(self.celery_broker_url),
            "result_backend": str(self.celery_result_backend),
            "worker_concurrency": self.celery_worker_concurrency,
            "task_always_eager": self.celery_task_always_eager,
            "task_serializer": "json",
            "accept_content": ["json"],
            "result_serializer": "json",
            "timezone": "UTC",
            "enable_utc": True,
        }
    
    @property
    def ml_config(self) -> Dict[str, Any]:
        """Get machine learning configuration dictionary."""
        return {
            "model_path": str(self.model_path),
            "ensemble_strategy": self.ensemble_strategy,
            "prediction_threshold": self.prediction_threshold,
            "embedding_model": self.embedding_model,
            "max_features": self.max_features,
        }
    
    @property
    def agent_config(self) -> Dict[str, Any]:
        """Get agent configuration dictionary."""
        return {
            "pool_size": self.agent_pool_size,
            "collection_interval": self.collection_interval,
            "analysis_batch_size": self.analysis_batch_size,
            "max_retries": self.max_retries,
            "timeout": self.agent_timeout,
        }
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        allow_mutation = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Uses lru_cache to ensure settings are loaded only once
    and reused throughout the application lifecycle.
    
    Returns:
        Settings: Configured application settings
    """
    return Settings()


# Global settings instance
settings = get_settings()


def get_database_url() -> str:
    """Get database URL string."""
    return str(settings.database_url)


def get_redis_url() -> str:
    """Get Redis URL string."""
    return str(settings.redis_url)


def is_development() -> bool:
    """Check if running in development mode."""
    return settings.is_development


def is_production() -> bool:
    """Check if running in production mode."""
    return settings.is_production


def is_testing() -> bool:
    """Check if running in test mode."""
    return settings.is_testing