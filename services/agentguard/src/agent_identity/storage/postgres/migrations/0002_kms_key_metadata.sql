-- AgentGuard Step 5: KMS/HSM key metadata ledger, schema v2.
-- Holds no key material of any kind: key ids, versions, lifecycle states and deadlines only.
-- Private keys live inside the KMS/HSM provider (never here, never in Redis).

CREATE TABLE kms_keys (
  key_id          TEXT PRIMARY KEY,
  provider        TEXT NOT NULL,
  algorithm       TEXT NOT NULL CHECK (algorithm IN ('ed25519')),
  key_type        TEXT NOT NULL CHECK (key_type IN ('asymmetric_signature','symmetric')),
  usages          TEXT[] NOT NULL,
  org_id          TEXT,
  purpose         TEXT NOT NULL DEFAULT '',
  created_at      DOUBLE PRECISION NOT NULL,
  created_by      TEXT NOT NULL,
  row_created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  row_updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX kms_keys_provider_idx ON kms_keys (provider);
CREATE INDEX kms_keys_org_idx ON kms_keys (org_id) WHERE org_id IS NOT NULL;

CREATE TABLE kms_key_versions (
  key_id          TEXT NOT NULL REFERENCES kms_keys(key_id) ON DELETE CASCADE,
  version         INTEGER NOT NULL CHECK (version >= 1),
  provider_key_id TEXT NOT NULL,            -- provider-native handle (ARN / token label); holds nothing sensitive
  state           TEXT NOT NULL CHECK (state IN ('pending','enabled','disabled','retiring',
                                                 'retired','revoked','destroyed')),
  public_key_b64  TEXT,
  fingerprint     TEXT NOT NULL DEFAULT '',
  usages          TEXT[] NOT NULL,
  exportable      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      DOUBLE PRECISION NOT NULL,
  enabled_at      DOUBLE PRECISION,
  retire_at       DOUBLE PRECISION,
  retired_at      DOUBLE PRECISION,
  revoked_at      DOUBLE PRECISION,
  revoke_reason   TEXT,
  PRIMARY KEY (key_id, version)
);
CREATE INDEX kms_key_versions_state_idx ON kms_key_versions (state);

-- defence in depth: a version's key identity is immutable; terminal states are terminal.
CREATE FUNCTION ag_guard_kms_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.key_id <> OLD.key_id OR NEW.version <> OLD.version THEN
    RAISE EXCEPTION 'kms version identity is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.state IN ('retired','revoked','destroyed') AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION 'kms key version state is terminal' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER kms_key_versions_guard BEFORE UPDATE ON kms_key_versions
  FOR EACH ROW EXECUTE FUNCTION ag_guard_kms_version();
