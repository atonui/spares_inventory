"""An explicit, immutable sequence; never discover executable migration files."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable
from . import v0001_core_schema,v0002_transfer_lifecycle,v0003_archiving_integrity,v0004_timezone_preferences,v0005_canonical_instants,v0006_announcement_dismissals,v0007_mobile_pairing,v0008_mobile_device_sessions

@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    checksum: str
    upgrade: Callable
    validate: Callable

MIGRATIONS=tuple(Migration(module.VERSION,module.NAME,sha256(Path(module.__file__).read_bytes()).hexdigest(),module.upgrade,module.validate)
                 for module in (v0001_core_schema,v0002_transfer_lifecycle,v0003_archiving_integrity,v0004_timezone_preferences,v0005_canonical_instants,v0006_announcement_dismissals,v0007_mobile_pairing,v0008_mobile_device_sessions))
