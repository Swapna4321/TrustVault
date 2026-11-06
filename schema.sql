-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL
        CHECK (role IN ('admin', 'owner', 'viewer')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users
ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

-- 2. DOCUMENTS TABLE
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    owner_id INTEGER NOT NULL REFERENCES users(id),
    storage_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. PERMISSIONS TABLE
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_type VARCHAR(10) NOT NULL
        CHECK (access_type IN ('READ', 'EDIT')),
    granted_by INTEGER REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (document_id, user_id)
);

-- 4. AUDIT LOGS TABLE
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    document_id INTEGER,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    prev_hash CHAR(64),
    entry_hash CHAR(64)
);

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash CHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash CHAR(64);
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_document_id_fkey;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS audit_chain_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    head_hash CHAR(64) NOT NULL
);

DO $$
DECLARE
    audit_row RECORD;
    previous_hash TEXT := repeat('0', 64);
    payload TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.audit_chain_state) THEN
        FOR audit_row IN
            SELECT id, user_id, document_id, action, details, success, created_at
            FROM public.audit_logs
            ORDER BY id
        LOOP
            payload := jsonb_build_object(
                'id', audit_row.id,
                'user_id', audit_row.user_id,
                'document_id', audit_row.document_id,
                'action', audit_row.action,
                'details', audit_row.details,
                'success', audit_row.success,
                'created_at', audit_row.created_at,
                'prev_hash', previous_hash
            )::text;

            UPDATE public.audit_logs
            SET prev_hash = previous_hash,
                entry_hash = encode(
                    public.digest(convert_to(payload, 'UTF8'), 'sha256'),
                    'hex'
                )
            WHERE id = audit_row.id
            RETURNING entry_hash INTO previous_hash;
        END LOOP;

        INSERT INTO public.audit_chain_state (singleton, head_hash)
        VALUES (TRUE, previous_hash)
        ON CONFLICT (singleton) DO NOTHING;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.chain_audit_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    previous_hash TEXT;
    payload TEXT;
BEGIN
    INSERT INTO public.audit_chain_state (singleton, head_hash)
    VALUES (TRUE, repeat('0', 64))
    ON CONFLICT (singleton) DO NOTHING;

    SELECT rtrim(head_hash) INTO previous_hash
    FROM public.audit_chain_state
    WHERE singleton = TRUE
    FOR UPDATE;

    NEW.created_at := coalesce(NEW.created_at, CURRENT_TIMESTAMP);
    NEW.prev_hash := previous_hash;
    payload := jsonb_build_object(
        'id', NEW.id,
        'user_id', NEW.user_id,
        'document_id', NEW.document_id,
        'action', NEW.action,
        'details', NEW.details,
        'success', NEW.success,
        'created_at', NEW.created_at,
        'prev_hash', previous_hash
    )::text;
    NEW.entry_hash := encode(
        public.digest(convert_to(payload, 'UTF8'), 'sha256'),
        'hex'
    );

    UPDATE public.audit_chain_state
    SET head_hash = NEW.entry_hash
    WHERE singleton = TRUE;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.reject_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_chain_insert ON audit_logs;
CREATE TRIGGER audit_logs_chain_insert
BEFORE INSERT ON audit_logs
FOR EACH ROW EXECUTE FUNCTION public.chain_audit_insert();

DROP TRIGGER IF EXISTS audit_logs_no_change ON audit_logs;
CREATE TRIGGER audit_logs_no_change
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION public.reject_audit_mutation();

DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER audit_logs_no_truncate
BEFORE TRUNCATE ON audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_audit_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_logs FROM PUBLIC;
REVOKE ALL ON public.audit_chain_state FROM PUBLIC;