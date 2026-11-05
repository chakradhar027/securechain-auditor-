from fastapi import APIRouter
from app.api.routes.upload import router as upload_router
from app.api.routes.contracts import router as contracts_router
from app.api.routes.scanner import router as scanner_router
from app.api.routes.findings import router as findings_router
from app.api.routes.history import router as history_router
from app.api.routes.reports import router as reports_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(upload_router)
api_router.include_router(contracts_router)
api_router.include_router(scanner_router)
api_router.include_router(findings_router)
api_router.include_router(history_router)
api_router.include_router(reports_router)
