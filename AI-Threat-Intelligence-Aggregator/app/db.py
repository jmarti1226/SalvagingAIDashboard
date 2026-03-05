from sqlmodel import SQLModel, Session, create_engine

# Shared SQLite engine used by the app.
ENGINE = create_engine(
    "sqlite:///intel.db",
    echo=False,
    connect_args={
        # Allow readers/writers a bit more time before SQLite raises "database is locked".
        "timeout": 30,
        "check_same_thread": False,
    },
)

# Create database tables from SQLModel metadata.
def init_db() -> None:
    SQLModel.metadata.create_all(ENGINE)

# FastAPI dependency that provides a per-request database session.
def get_session():
    """Yield a transactional SQLModel session for request handlers."""
    with Session(ENGINE) as session:
        yield session
