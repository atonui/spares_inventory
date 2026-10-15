"""Ordered, immutable definitions for PostgreSQL schema changes."""

from dataclasses import dataclass
from hashlib import sha256

from . import v0001_core_schema, v0002_tenancy, v0003_tenant_policies


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
    for module in (v0001_core_schema, v0002_tenancy, v0003_tenant_policies)
)


def validate_registry(migrations=MIGRATIONS) -> None:
    versions = tuple(migration.version for migration in migrations)
    if versions != tuple(range(1, len(versions) + 1)):
        raise ValueError("PostgreSQL migration versions must be ordered and contiguous from 1")
    if len({migration.name for migration in migrations}) != len(migrations):
        raise ValueError("PostgreSQL migration names must be unique")


validate_registry()
