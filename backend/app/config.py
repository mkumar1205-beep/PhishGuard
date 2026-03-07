from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GROQ_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    REDIS_URL: str = "redis://localhost:6379"
    SANDBOX_URL: str = ""          # set to http://sandbox:8001 in Docker
    CACHE_TTL_SECONDS: int = 3600  # 1 hour

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()