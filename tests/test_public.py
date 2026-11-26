"""Public behaviour checks for the registry permission layer."""

from regperm import (
    check_delete,
    check_pull,
    check_push,
    parse_role,
    registry_batch,
)

POLICY = {
    "roles": {
        "admin": {"push": True, "pull": True, "delete": True},
        "writer": {"push": True, "pull": True, "delete": False},
        "reader": {"push": False, "pull": True, "delete": False},
    },
    "anonymous": False,
    "audit": True,
}

NOW = "2026-11-19T09:30:00Z"


def test_parse_role_resolves_role_names():
    parsed = parse_role("ADMIN")

    assert parsed["name"] == "admin"
    assert parsed["push"] is True
    assert parsed["delete"] is True


def test_check_push_blocks_read_only_roles():
    assert check_push("reader", "prod/app") is False
    assert check_push("writer", "prod/app") is True
    assert check_push(None, "prod/app") is False


def test_check_pull_allows_read_only_roles():
    assert check_pull("viewer", "prod/app", False) is True
    assert check_pull("readonly", "prod/app", False) is True
    assert check_pull(None, "prod/app", False) is False
    assert check_pull(None, "prod/app", True) is True


def test_check_delete_requires_administrator():
    assert check_delete("admin", NOW) is True
    assert check_delete("writer", NOW) is False
    assert check_delete("admin", None) is False


def test_registry_batch_keeps_requests_independent():
    outcome = registry_batch(
        [
            {
                "id": "first",
                "action": "push",
                "role": "admin",
                "namespace": "prod/app",
            },
            {
                "id": "second",
                "action": "push",
                "namespace": "prod/app",
            },
        ],
        POLICY,
        NOW,
    )

    assert outcome["total"] == 2
    assert outcome["results"][0]["allowed"] is True
    assert outcome["results"][1]["allowed"] is False
    assert len(outcome["results"][1]["audit"]) == 1