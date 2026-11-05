import pytest
from app.database.connection import init_db

@pytest.fixture(autouse=True)
async def setup_test_database():
    """Ensure database tables exist before test execution."""
    await init_db()
    yield
