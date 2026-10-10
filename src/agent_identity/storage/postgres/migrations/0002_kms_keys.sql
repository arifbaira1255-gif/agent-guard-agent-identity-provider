-- Step 5: enterprise KMS/HSM key management metadata. Schema v2.
--
-- NON-SECRET metadata ONLY. Private key material lives inside the provider (Vault Transit
-- or a PKCS#11 token) and is NEVER stored here — there is no encrypted_private column.
-- The pre-existing keystore_keys table (migration 0001) is left untouched so existing
-- deployments and credentials keep working; new keys are created through the KMS.

CREATE TABLE kms_keys (
  key_id               TEXT PRIMARY KEY,
  provider             TEXT NOT NULL CHECK (provider IN ('local','vault','pkcs11')),
  algorithm            TEXT NOT NULL CHECK (algorithm IN ('ed25519')),
  status               TEXT NOT NULL CHECK (status IN
                          ('pending','active','rotating','retiring','retired','revoked')),
  created_at           DOUBLE PRECISION NOT NULL,
  public_key           TEXT NOT NULL,          -- base64url raw Ed25519 (verification material)
  fingerprint          TEXT NOT NULL,
  version              INTEGER NOT NULL DEFAULT 1,
  external_ref         TEXT,                   -- provider handle (vault key name / CKA_ID); NULL once destroyed
  not_after            DOUBLE PRECISION,       -- overlap deadline while rotating/retiring
  rotates_to           TEXT,                   -- successor key id
  rotated_from         TEXT,                   -- predecessor key id
  revoked_reason       TEXT,
  revoke_effective_at  DOUBLE PRECISION,
  exportable           BOOLEAN NOT NULL DEFAULT false,
  created_by           TEXT NOT NULL DEFAULT 'system',
  tenant_id            TEXT,
  labels               TEXT[] NOT NULL DEFAULT '{}',
  row_created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (key_id <> '' ),
  CHECK (rotates_to IS NULL OR rotates_to <> key_id),
  CHECK (rotated_from IS NULL OR rotated_from <> key_id),
  -- a revoked key must record when the revocation took effect
  CHECK (status <> 'revoked' OR revoke_effective_at IS NOT NULL)
);
CREATE INDEX kms_keys_status_idx ON kms_keys (status);
CREATE INDEX kms_keys_tenant_idx ON kms_keys (tenant_id) WHERE tenant_id IS NOT NULL;

-- Irreversible: a revoked key may never return to any non-revoked state, and a destroyed
-- key (external_ref NULLed) may not be reactivated by writing a new external_ref.
CREATE FUNCTION ag_guard_kms_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'revoked key is terminal' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.key_id <> OLD.key_id OR NEW.provider <> OLD.provider
     OR NEW.algorithm <> OLD.algorithm OR NEW.created_at <> OLD.created_at
     OR NEW.public_key <> OLD.public_key THEN
    RAISE EXCEPTION 'immutable key identity changed' USING ERRCODE = 'check_violation';
  END IF;
  NEW.row_updated_at := now();
  RETURN NEW;
END $$;

CREATE TRIGGER kms_keys_guard BEFORE UPDATE ON kms_keys
  FOR EACH ROW EXECUTE FUNCTION ag_guard_kms_key();

-- Append-only audit trail for key administration. NO key material, tokens or secrets.
CREATE TABLE kms_key_audit (
  id              BIGSERIAL PRIMARY KEY,
  event           TEXT NOT NULL,
  key_id          TEXT,
  provider        TEXT,
  algorithm       TEXT,
  result          TEXT NOT NULL DEFAULT 'ok',
  reason          TEXT,
  actor           TEXT,
  correlation_id  TEXT,
  detail          TEXT,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX kms_key_audit_key_idx ON kms_key_audit (key_id);
CREATE INDEX kms_key_audit_event_idx ON kms_key_audit (event, row_created_at);
