from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings
from app.database.base import Base

# SQLAlchemy async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def init_db() -> None:
    # Import all models so that Base has them registered
    import app.models.contract
    import app.models.scan
    import app.models.finding
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        def run_migrations(connection):
            from sqlalchemy import inspect, text
            inspector = inspect(connection)
            if "scans" in inspector.get_table_names():
                columns = [col["name"] for col in inspector.get_columns("scans")]
                if "engines_requested" not in columns:
                    connection.execute(text("ALTER TABLE scans ADD COLUMN engines_requested JSON DEFAULT '[]'"))

            if "contracts" in inspector.get_table_names():
                res = connection.execute(text("SELECT id, name, filename, source_code FROM contracts WHERE name = 'adopting' OR name LIKE 'SmartContract%'"))
                rows = res.fetchall()
                if rows:
                    from app.utils.file_validator import extract_contract_name
                    for row_id, old_name, filename, source_code in rows:
                        new_name = extract_contract_name(source_code, filename=filename)
                        if new_name and new_name != old_name:
                            connection.execute(text("UPDATE contracts SET name = :name WHERE id = :id"), {"name": new_name, "id": row_id})

        await conn.run_sync(run_migrations)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

