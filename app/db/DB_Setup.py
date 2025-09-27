# db_handler.py
import configparser
import ssl
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from contextlib import asynccontextmanager
from typing import AsyncGenerator,Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import time
import os
from dotenv import load_dotenv

load_dotenv()

ssl_context = ssl.create_default_context()
# Disable hostname check (needed for Supabase free tier self-signed cert)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE  # skip certificate verification for local/dev

SUPABASE_CONNECTION_STRING=os.getenv("SUPABASE_CONNECTION_STRING")
Base = declarative_base()

class DBHandler:
    def __init__(self):
        # cfg = configparser.ConfigParser()
        # cfg.read(config_file)

        # Load PostgreSQL connection string from config
        # Example inside app.config:
        # [database]
        # db = postgresql+asyncpg://postgres:password@localhost:5432/chatdb
        self.conn_str = SUPABASE_CONNECTION_STRING

        # Setup SQLAlchemy async engine & session
        self.engine = create_async_engine(
                                        self.conn_str,
                                        echo=False,  # keep True only if debugging SQL
                                        future=True,
                                        connect_args={"ssl": ssl_context},
                                        pool_size=5,         # maintain 5 persistent connections
                                        max_overflow=10,     # allow 10 extra if needed
                                        pool_timeout=30,     # wait before failing
                                        pool_recycle=1800,   # recycle every 30 minutes
                                    )

        self._session = sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Async context manager for DB session."""
        t0 = time.time()
   
        print("Session creation took", time.time() - t0, "seconds")
        session = self._session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


class UserDBHandler(DBHandler):

    def __init__(self):
        super().__init__()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")
    
    def verify_password(self, plain_password: str, password_hash: str) -> bool:
        return self.pwd_context.verify(plain_password, password_hash)
    

    async def create_user(
            self,
            username:str,
            email:str,
            password:str,
            full_name:str,
            role :str = 'user'

    ) -> Optional[dict]:
        password_hash = self.pwd_context.hash(password)
        now = datetime.now(timezone.utc)

        sql = text("""
                INSERT INTO users (username, email, password_hash, full_name, role, created_at, updated_at)
                VALUES (:username, :email, :password_hash, :full_name, :role, :created_at, :updated_at)
                ON CONFLICT (email) DO NOTHING
                RETURNING id, username, email;
                   """)
        params = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "full_name": full_name,
            "role": role,
            "created_at": now,
            "updated_at": now,
        }
        async with self.get_session() as session:
            result = await session.execute(sql,params)
            row = result.fetchone()
            if row:
                return {
                    "id":row.id,
                    "username":row.username,
                    "email":row.email
                }
            return None
    
    async def get_existing_user(
            self,
            email:str

    ) -> Optional[dict]:
        sql = text("""
                   SELECT * FROM users
                   WHERE email= :email
                   """
                   )

        params = {
            "email":email
        }                         
        async with self.get_session() as session:
            result = await session.execute(sql, params)
            row = result.fetchone()
            if row :
                return {
                    "message":"email already exists",
                    "id":row.id,
                    "email":row.email,
                    "password_hash":row.password_hash,
                    "full_name":row.full_name,
                    "username":row.username,
                    "role":row.role
                }
            return None
