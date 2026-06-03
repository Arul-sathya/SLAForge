from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    app_name: str = "SLAForge"
    app_version: str = "1.0.0"
    log_level: str = "INFO"

    database_url: str = "postgresql://slaforge:slaforge@postgres:5432/slaforge"

    anthropic_api_key: str = Field(..., description="Anthropic API key")
    claude_model: str = "claude-sonnet-4-6"
    diagnosis_max_tokens: int = 2048

    github_token: str = Field(..., description="GitHub personal access token")
    github_owner: str = Field(..., description="GitHub org or username")
    github_repo: str = Field(..., description="GitHub repo to monitor")
    github_webhook_secret: str = "slaforge_webhook_secret_changeme"

    cusum_threshold: float = 5.0
    cusum_drift: float = 0.5
    baseline_window: int = 60
    poll_interval_seconds: int = 30
    anomaly_trigger_score: float = 3.0

    runbook_path: str = "/data/runbook.md"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


settings = Settings()