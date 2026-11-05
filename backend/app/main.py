from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database.connection import init_db
from app.api.router import api_router
from app.utils.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SecureChain Auditor database tables...")
    await init_db()
    logger.info("Database initialized successfully.")
    yield
    logger.info("Shutting down SecureChain Auditor.")

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Intelligent Multi-Engine Smart Contract Vulnerability Detection and Risk Assessment Platform",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "version": "1.0.0"
    }

@app.get("/")
async def root():
    return {
        "message": "Welcome to SecureChain Auditor API",
        "docs_url": "/docs",
        "health_check": "/health",
        "api_prefix": "/api/v1"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
