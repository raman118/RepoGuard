"""Trusted operator provisioning; tokens go to stdout once, never the database."""

import argparse
import secrets

from repoguard.auth import token_digest
from repoguard.config import Settings
from repoguard.database import make_engine, sessions
from repoguard.models import Credential, Installation, Tenant


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    tenant = sub.add_parser("create-tenant")
    tenant.add_argument("name")
    installation = sub.add_parser("assign-installation")
    installation.add_argument("tenant_id")
    installation.add_argument("installation_id", type=int)
    revoke = sub.add_parser("revoke-token")
    revoke.add_argument("digest")
    args = parser.parse_args()
    with sessions(make_engine(Settings().database_url))() as db:
        if args.command == "create-tenant":
            token = secrets.token_urlsafe(32)
            row = Tenant(name=args.name)
            db.add(row)
            db.flush()
            db.add(Credential(digest=token_digest(token), tenant_id=row.id, actor=args.name))
            db.commit()
            print(f"Tenant: {row.id}\nBearer token (store securely): {token}")
        elif args.command == "assign-installation":
            if db.get(Tenant, args.tenant_id) is None or args.installation_id <= 0:
                parser.error("valid tenant and positive installation ID required")
            db.add(Installation(id=args.installation_id, tenant_id=args.tenant_id))
            db.commit()
        elif args.command == "revoke-token":
            credential = db.get(Credential, args.digest)
            if credential is None:
                parser.error("credential digest not found")
            credential.active = False
            db.commit()


if __name__ == "__main__":
    main()
