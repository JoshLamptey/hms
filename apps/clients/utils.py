import re
import logging
from django.db import connection
from psycopg2 import sql

logger = logging.getLogger(__name__)

SAFE_SCHEMA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def generate_schema_name(name: str) -> str:
    name = name.lower().strip()
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^a-z0-9_]", "", name)
    name = re.sub(r"_+", "_", name).strip("_")

    if not name or not name[0].isalpha():
        name = f"org_{name}"

    return name[:63]

def create_schema_for_client(client) -> str:
    schema_name = client.schema_name

    if not schema_name:
        raise ValueError(f"Client '{client}' has no schema_name set.")

    if not SAFE_SCHEMA_NAME.match(schema_name):
        raise ValueError(f"Unsafe schema name on client: {schema_name!r}")

    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                sql.Identifier(schema_name)
            )
        )

    logger.info(f"Schema '{schema_name}' created for client '{client.name}'.")

    # schema_name is already persisted before the signal fires,
    # so no client.save() needed here.
    return schema_name