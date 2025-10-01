from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ConnectionFailure
from loguru import logger

from src.core.config import settings


class DatabaseManager:
    """Database connection manager for MongoDB"""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
    
    async def connect(self) -> None:
        """Establish database connection"""
        try:
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                maxPoolSize=50,
                minPoolSize=10,
                maxIdleTimeMS=30000,
                serverSelectionTimeoutMS=5000,
            )
            
            # Test the connection
            await self.client.admin.command('ping')
            
            self.database = self.client[settings.MONGODB_DB_NAME]
            
            logger.info(f"Connected to MongoDB database: {settings.MONGODB_DB_NAME}")
            
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close database connection"""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    async def create_indexes(self) -> None:
        """Create database indexes for optimal performance"""
        if not self.database:
            return
        
        try:
            # Connectors collection indexes
            await self.database.connectors.create_index([("tenant_id", 1), ("connector_id", 1)], unique=True)
            await self.database.connectors.create_index([("tenant_id", 1)])
            await self.database.connectors.create_index([("status", 1)])
            
            # Workflows collection indexes
            await self.database.workflows.create_index([("tenant_id", 1)])
            await self.database.workflows.create_index([("tenant_id", 1), ("status", 1)])
            await self.database.workflows.create_index([("created_at", -1)])
            
            # Webhook events collection indexes
            await self.database.webhook_events.create_index([("tenant_id", 1)])
            await self.database.webhook_events.create_index([("connector_id", 1)])
            await self.database.webhook_events.create_index([("event_type", 1)])
            await self.database.webhook_events.create_index([("created_at", -1)])
            
            # Audit logs collection indexes
            await self.database.audit_logs.create_index([("tenant_id", 1)])
            await self.database.audit_logs.create_index([("user_id", 1)])
            await self.database.audit_logs.create_index([("action", 1)])
            await self.database.audit_logs.create_index([("timestamp", -1)])
            
            # Metrics collection indexes
            await self.database.metrics.create_index([("metric_name", 1)])
            await self.database.metrics.create_index([("timestamp", -1)])
            await self.database.metrics.create_index([("tenant_id", 1)])
            
            logger.info("Database indexes created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create database indexes: {e}")
            raise


# Global database manager instance
db_manager = DatabaseManager()


# PUBLIC_INTERFACE
async def init_db() -> None:
    """
    Initialize database connection and create indexes.
    
    This function should be called during application startup.
    """
    await db_manager.connect()
    await db_manager.create_indexes()


# PUBLIC_INTERFACE
async def get_database() -> AsyncIOMotorDatabase:
    """
    Get the database instance.
    
    Returns:
        AsyncIOMotorDatabase: MongoDB database instance
        
    Raises:
        RuntimeError: If database is not initialized
    """
    if db_manager.database is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return db_manager.database


# PUBLIC_INTERFACE
async def close_db() -> None:
    """
    Close database connection.
    
    This function should be called during application shutdown.
    """
    await db_manager.disconnect()
