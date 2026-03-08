import re
from django.db import connection
import logging

logger = logging.getLogger(__name__)


SAFE_SCHEMA_NAME = re.compile(r'^[a-z][a-z0-9_]{0,62}$')

def sanitize_schema_name(name:str)->str:
    name = name.lower().strip() 
    name = re.sub(r'\s+', '_', name)
    name = re.sub(r'[^a-z0-9_]', '', name)
    
    if not name or not name[0].isalpha():
        name = f"org_{name}"
    return name[:63]
   
def create_schema_for_client(client)->str:
    """
    Creates a PostgreSQL schema for the given Client instance.
    Uses org_slug as the schema name, falls back to sanitized name.
    Returns the schema name created.
    Raises ValueError if the derived name is unsafe.
    """
    raw = client.org_slug or client.name
    if not raw:
        raise ValueError(f"Client '{client}' has neither org_slug nor name set.")

    schema_name = sanitize_schema_name(raw)
    
    if not SAFE_SCHEMA_NAME.match(schema_name):
        raise ValueError(f"Could not derive a safe schema name from: {raw!r}")
    
    with connection.cursor() as cursor:
        cursor.execute(
            f"CREATE SCHEMA IF NOT EXISTS {schema_name};"
        )
    
    logger.info(f"Schema '{schema_name}' created for client '{client.name}'.")
    return schema_name