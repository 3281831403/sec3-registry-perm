"""Registry permission checks."""

from .policy import (
    FLAGS,
    ROLE_ALIASES,
    ROLE_TABLE,
    WRITE_ACTIONS,
    authorize,
    check_delete,
    check_inherit,
    check_pull,
    check_push,
    parse_role,
    registry_batch,
    validate_policy,
)

__all__ = [
    "FLAGS",
    "ROLE_ALIASES",
    "ROLE_TABLE",
    "WRITE_ACTIONS",
    "authorize",
    "check_delete",
    "check_inherit",
    "check_pull",
    "check_push",
    "parse_role",
    "registry_batch",
    "validate_policy",
]