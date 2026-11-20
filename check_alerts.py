
from database import connect_database

with connect_database() as connection:

    tables = connection.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
    """).fetchall()

    print("Database tables:")

    for table in tables:
        print("-", table["name"])

    columns = connection.execute("""
        PRAGMA table_info(security_alerts)
    """).fetchall()

    print("\nSecurity alerts columns:")

    for column in columns:
        print("-", column["name"])
