from __future__ import annotations

import os
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine


# Database file lives alongside the JSON reports
_DB_DIR = Path(os.getenv("REDCHAIN_DATA_DIR", "./redchain_data"))
_DB_PATH = _DB_DIR / "redchain.db"

engine = create_engine(
    f"sqlite:///{_DB_PATH.resolve()}",
    connect_args = {"check_same_thread": False},
    echo = False,
)

def init_db() -> None:
    """ Create all tables if they don't exist yet. """

    _DB_DIR.mkdir(parents = True, exist_ok = True)
    SQLModel.metadata.create_all(engine)


def get_session():
    """ FastAPI dependency that provides a DB session per request. """
    
    with Session(engine) as session:
        yield session