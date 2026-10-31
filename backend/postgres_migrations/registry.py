"""Ordered, immutable definitions for PostgreSQL schema changes."""

from dataclasses import dataclass
from hashlib import sha256

from . import (
    v0001_core_schema,
    v0002_tenancy,
    v0003_tenant_policies,
    v0004_tenant_administration,
    v0005_hashed_sessions,
    v0006_native_refresh_credentials,
    v0007_mail_outbox_counts,
    v0008_password_reset_mail,
    v0009_email_change_verification,
    v0010_mobile_pairing,
    v0011_mobile_device_sessions,
    v0012_mobile_stock_adjustments,
    v0013_platform_audit_indexes,
    v0014_organization_invitation_mail_counts,
    v0015_platform_support_sessions,
    v0016_resend_delivery_webhooks,
    v0017_store_activity_emails,
    v0018_mobile_pairing_manual_code,
    v0019_mobile_session_policy,
    v0020_platform_tenant_identity_separation,
)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        contents = f"{self.version}:{self.name}\n" + "\n".join(self.statements)
        return sha256(contents.encode("utf-8")).hexdigest()


MIGRATIONS = tuple(
    Migration(module.VERSION, module.NAME, module.SQL)
    for module in (
        v0001_core_schema,
        v0002_tenancy,
        v0003_tenant_policies,
        v0004_tenant_administration,
        v0005_hashed_sessions,
        v0006_native_refresh_credentials,
        v0007_mail_outbox_counts,
        v0008_password_reset_mail,
        v0009_email_change_verification,
        v0010_mobile_pairing,
        v0011_mobile_device_sessions,
        v0012_mobile_stock_adjustments,
        v0013_platform_audit_indexes,
        v0014_organization_invitation_mail_counts,
        v0015_platform_support_sessions,
        v0016_resend_delivery_webhooks,
        v0017_store_activity_emails,
        v0018_mobile_pairing_manual_code,
        v0019_mobile_session_policy,
        v0020_platform_tenant_identity_separation,
    )
)


def validate_registry(migrations=MIGRATIONS) -> None:
    versions = tuple(migration.version for migration in migrations)
    if versions != tuple(range(1, len(versions) + 1)):
        raise ValueError("PostgreSQL migration versions must be ordered and contiguous from 1")
    if len({migration.name for migration in migrations}) != len(migrations):
        raise ValueError("PostgreSQL migration names must be unique")


validate_registry()
