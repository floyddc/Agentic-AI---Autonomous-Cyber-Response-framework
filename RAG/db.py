from contextlib import contextmanager
import psycopg2
import psycopg2.extras
from . import config

def connect(dbname: str):

    return psycopg2.connect(
        host=config.POSTGRES_HOST,
        port=config.POSTGRES_PORT,
        dbname=dbname,
        user=config.POSTGRES_USER,
        password=config.POSTGRES_PASSWORD,
    )

@contextmanager
def cursor(dbname: str):
    conn = connect(dbname)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    finally:
        conn.close()
