-- DoorSense PostgreSQL setup
-- Run as the postgres superuser:  sudo -u postgres psql -f db_setup.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'doorsense') THEN
    CREATE USER doorsense WITH PASSWORD 'doorsense';
  END IF;
END
$$;

CREATE DATABASE doorsense OWNER doorsense;

\connect doorsense

GRANT ALL PRIVILEGES ON DATABASE doorsense TO doorsense;
GRANT ALL ON SCHEMA public TO doorsense;
