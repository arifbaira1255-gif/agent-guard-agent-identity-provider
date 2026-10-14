"""CLI:  python -m agent_identity.storage.postgres {migrate|status|check}   (config from AGENTGUARD_PG_* env)
Use a MIGRATOR role (DDL rights) for `migrate`; the runtime role needs only SELECT/INSERT/UPDATE."""
import json
import sys

from . import migrate
from .config import PgConfig
from .db import Database


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    if cmd not in ("migrate", "status", "check"):
        print(__doc__)
        return 2
    db = Database(PgConfig.from_env())
    try:
        if cmd == "migrate":
            print(json.dumps({"applied": migrate.migrate(db), "version": migrate.current_version(db)}))
        elif cmd == "status":
            print(json.dumps({"db_version": migrate.current_version(db), "code_version": migrate.expected_version()}))
        else:
            print(json.dumps(db.readiness()))
            return 0 if db.readiness()["ready"] else 1
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
