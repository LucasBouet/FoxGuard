""""Anyone may use this" becomes something an operator states.

Revision ID: 0009_public_service_auth
Revises: 0008_sso_authorization
Create Date: Phase 7e

One enum value. ``service_auth_kind`` gains ``public``, the authenticator that
demands nothing -- what a reverse proxy in front of a public web site needs, and
until now the one thing the model could not express: an empty authenticator list
is refused precisely so that a service nobody guarded cannot be mistaken for a
service somebody opened on purpose.

Nothing existing changes. No row is written, no default moves, and a deployment
that never publishes a public service renders byte-identical output afterwards.

The value is added rather than the type recreated because recreating it would
mean dropping the column's default, rewriting every ``service_auth`` row and
recreating ``uq_service_auth_kind`` -- a table rewrite to add a string. On
PostgreSQL 12 and later ``ADD VALUE`` is transactional as long as the new value
is not *used* in the same transaction, which nothing here does.

The downgrade leaves the value in place. PostgreSQL cannot remove an enum value,
and the alternative -- recreate the type, and with it the column, the default
and the constraint -- would risk the schema to undo something inert. It is
guarded instead: downgrading with public authenticators still in the table would
leave rows the older code cannot render, so the migration refuses rather than
producing a gateway that 500s on its next poll.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0009_public_service_auth"
down_revision = "0008_sso_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE service_auth_kind ADD VALUE IF NOT EXISTS 'public'")


def downgrade() -> None:
    remaining = op.get_bind().execute(
        sa.text("SELECT count(*) FROM service_auth WHERE kind = 'public'")
    ).scalar_one()
    if remaining:
        raise RuntimeError(
            f"{remaining} authenticator(s) still use kind='public'. Downgrading "
            "would leave rows the earlier renderer refuses, and the gateway "
            "would stop applying any proxy configuration at all. Delete them, or "
            "give those services a real authenticator, and run this again."
        )
    # The enum value stays. It is unreachable with no rows using it, and
    # PostgreSQL offers no DROP VALUE -- see the module docstring.
