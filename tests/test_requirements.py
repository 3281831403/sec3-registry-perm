"""Requirement-level verification for the registry permission layer.

Each test maps back to a rule from the task statement:
- push and pull are independent permissions;
- anonymous access is off unless explicitly enabled;
- delete is admin-only and always audited;
- child namespaces may only tighten, never widen;
- rename checks both source and target namespaces;
- batch decisions are independent;
- read-only roles can never push; every write leaves an audit record.
"""

from regperm import (
    authorize,
    check_delete,
    check_inherit,
    check_pull,
    check_push,
    parse_role,
    registry_batch,
    validate_policy,
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


# --- role resolution -------------------------------------------------------

def test_reader_alias_is_not_writer():
    # The planted alias mapped "reader" to writer; that grants push.
    assert parse_role("reader")["name"] == "reader"
    assert parse_role("reader")["push"] is False
    assert parse_role("viewer")["name"] == "reader"
    assert parse_role("readonly")["push"] is False
    assert parse_role("reader")["pull"] is True


def test_role_names_are_case_and_whitespace_insensitive():
    assert parse_role("  ADMIN ")["name"] == "admin"
    assert parse_role("Writer")["name"] == "writer"
    assert parse_role(" ReAdEr ")["push"] is False


def test_pull_flag_is_independent_from_push_flag():
    # Planted bug copied the push flag into pull; reader push=False would
    # therefore lose pull, and the two permissions would not be separate.
    reader = parse_role("reader")
    assert reader["push"] is False and reader["pull"] is True
    writer = parse_role("writer")
    assert writer["push"] is True and writer["pull"] is True and writer["delete"] is False


def test_anonymous_and_unknown_roles_deny_everything():
    for value in (None, "", "  ", "anonymous", "GUEST", "guest"):
        parsed = parse_role(value)
        assert parsed["name"] == "anonymous"
        assert parsed["push"] is False and parsed["pull"] is False and parsed["delete"] is False
    unknown = parse_role("superuser")
    assert unknown["name"] == "unknown"
    assert unknown["push"] is False and unknown["pull"] is False and unknown["delete"] is False


def test_role_mapping_form_preserves_independent_flags():
    parsed = parse_role(
        {"name": "CUSTOM", "push": True, "pull": False, "delete": False, "scope": ["team-a"]}
    )
    assert parsed["name"] == "custom"
    assert parsed["push"] is True and parsed["pull"] is False and parsed["delete"] is False
    assert parsed["scope"] == ["team-a"]


# --- push / pull separation ------------------------------------------------

def test_read_only_roles_can_never_push():
    for role in ("reader", "viewer", "readonly", None, "", "anonymous", "guest", "nobody"):
        assert check_push(role, "prod/app") is False, role
        decision = authorize(
            {"id": "p", "action": "push", "role": role, "namespace": "prod/app"},
            POLICY,
            NOW,
        )
        assert decision["allowed"] is False
        assert decision["reason"] == "push_denied"


def test_scope_restricts_push_to_owned_namespace_tree():
    scoped = {"name": "writer", "push": True, "pull": True, "delete": False, "scope": ["team-a"]}
    assert check_push(scoped, "team-a/app") is True
    assert check_push(scoped, "team-a/sub/app") is True
    assert check_push(scoped, "team-b/app") is False


def test_anonymous_pull_requires_explicit_opt_in():
    # None means "never configured" and must behave like off.
    assert check_pull(None, "prod/app", None) is False
    assert check_pull(None, "prod/app", False) is False
    assert check_pull("guest", "prod/app", None) is False
    assert check_pull(None, "prod/app", True) is True


def test_authorize_anonymous_defaults_from_policy_and_fails_closed():
    request = {"id": "a", "action": "pull", "namespace": "prod/app"}
    assert authorize(request, {"roles": POLICY["roles"], "audit": True}, NOW)["allowed"] is False
    assert authorize(request, {"roles": POLICY["roles"], "anonymous": False, "audit": True}, NOW)["allowed"] is False
    enabled = authorize(request, {"roles": POLICY["roles"], "anonymous": True, "audit": True}, NOW)
    assert enabled["allowed"] is True


def test_deleted_image_cannot_come_back_via_anonymous_pull():
    # The headline failure: a deleted image was still anonymously pullable.
    decision = authorize(
        {"id": "pull", "action": "pull", "role": "anonymous", "namespace": "prod/app"},
        POLICY,
        NOW,
    )
    assert decision["allowed"] is False
    assert decision["reason"] == "pull_denied"


# --- delete ----------------------------------------------------------------

def test_delete_is_admin_only_with_a_valid_timestamp():
    assert check_delete("admin", NOW) is True
    assert check_delete("writer", NOW) is False
    assert check_delete("reader", NOW) is False
    assert check_delete(None, NOW) is False
    assert check_delete("admin", None) is False
    assert check_delete("admin", "") is False
    assert check_delete("admin", "not-a-timestamp") is False
    # Aliases must not widen delete either.
    assert check_delete("developer", NOW) is False


def test_every_delete_attempt_is_audited_allowed_or_denied():
    for role, expected in (("admin", True), ("writer", False), ("reader", False), (None, False)):
        decision = authorize(
            {"id": "d", "action": "delete", "role": role, "namespace": "prod/app", "target": "img:1"},
            POLICY,
            NOW,
        )
        assert decision["allowed"] is expected
        assert len(decision["audit"]) == 1
        record = decision["audit"][0]
        assert record["action"] == "delete"
        assert record["allowed"] is expected
        assert record["at"] == NOW
        assert record["target"] == "img:1"


def test_delete_without_timestamp_is_denied_but_still_audited():
    decision = authorize(
        {"id": "d", "action": "delete", "role": "admin", "namespace": "prod/app"},
        POLICY,
        None,
    )
    assert decision["allowed"] is False
    assert decision["reason"] == "delete_denied"
    assert len(decision["audit"]) == 1
    assert decision["audit"][0]["allowed"] is False


# --- namespace inheritance -------------------------------------------------

def test_child_namespace_can_only_tighten_permissions():
    parent = {"name": "prod", "parent": None, "push": True, "pull": True, "delete": True}

    tightening = {"name": "prod/app", "parent": "prod", "push": False, "pull": True, "delete": False}
    assert check_inherit(tightening, parent) is True

    widening_push = {"name": "prod/app", "parent": "prod", "push": True, "pull": True, "delete": False}
    restrictive_parent = {"name": "prod", "push": False, "pull": True, "delete": False}
    assert check_inherit(widening_push, restrictive_parent) is False

    widening_delete = {"name": "prod/app", "parent": "prod", "push": False, "pull": False, "delete": True}
    assert check_inherit(widening_delete, {"name": "prod", "push": False, "pull": False, "delete": False}) is False

    widening_pull = {"name": "prod/app", "parent": "prod", "push": False, "pull": True, "delete": False}
    assert check_inherit(widening_pull, {"name": "prod", "push": False, "pull": False, "delete": False}) is False


def test_inheritance_checks_parent_link_and_roots():
    parent = {"name": "prod", "push": True, "pull": True, "delete": True}
    child = {"name": "dev/app", "parent": "staging", "push": False, "pull": True, "delete": False}
    assert check_inherit(child, parent) is False  # parent link does not name "prod"

    root = {"name": "root-ns", "parent": None, "push": False, "pull": False, "delete": False}
    assert check_inherit(root, None) is True
    orphan = {"name": "root-ns", "parent": "elsewhere", "push": False, "pull": False, "delete": False}
    assert check_inherit(orphan, None) is False


# --- rename ----------------------------------------------------------------

def test_rename_checks_both_source_and_target_namespaces():
    request = {
        "id": "r",
        "action": "rename",
        "role": "writer",
        "namespace": "team-a/app",
        "target": "team-b/app",
    }
    scoped_policy = POLICY
    decision = authorize(request, scoped_policy, NOW)
    assert decision["allowed"] is True  # unscoped writer can write both

    scoped = {"name": "writer", "push": True, "pull": True, "delete": False, "scope": ["team-a"]}
    blocked = authorize(dict(request, role=scoped), scoped_policy, NOW)
    assert blocked["allowed"] is False
    assert blocked["reason"] == "rename_denied"
    assert len(blocked["audit"]) == 1  # rejected write is still audited


def test_rename_requires_target_and_audits():
    missing = authorize(
        {"id": "r", "action": "rename", "role": "writer", "namespace": "team-a/app"},
        POLICY,
        NOW,
    )
    assert missing["allowed"] is False
    assert missing["reason"] == "rename_target_missing"
    assert len(missing["audit"]) == 1


def test_rename_cannot_escape_a_read_only_source_namespace():
    # Reader cannot push anywhere, so neither side of the rename may pass.
    decision = authorize(
        {
            "id": "r",
            "action": "rename",
            "role": "reader",
            "namespace": "prod/app",
            "target": "dev/app",
        },
        POLICY,
        NOW,
    )
    assert decision["allowed"] is False
    assert decision["reason"] == "rename_denied"


# --- batch independence ----------------------------------------------------

def test_batch_each_request_is_judged_independently():
    outcome = registry_batch(
        [
            {"id": "first", "action": "push", "role": "admin", "namespace": "prod/app"},
            {"id": "second", "action": "push", "namespace": "prod/app"},
            {"id": "third", "action": "push", "role": "reader", "namespace": "prod/app"},
            {"id": "fourth", "action": "push", "role": "writer", "namespace": "prod/app"},
        ],
        POLICY,
        NOW,
    )
    assert outcome["total"] == 4
    assert outcome["allowed"] == 2
    assert [item["allowed"] for item in outcome["results"]] == [True, False, False, True]
    assert [item["index"] for item in outcome["results"]] == [0, 1, 2, 3]
    # A missing role must not inherit a neighbour's role (the planted leak).
    assert outcome["results"][1]["role"] == "anonymous"
    assert outcome["results"][2]["role"] == "reader"
    for item in outcome["results"]:
        assert len(item["audit"]) == 1


# --- audit invariant -------------------------------------------------------

def test_every_write_attempt_has_exactly_one_audit_record():
    cases = [
        ("push", "writer", True),
        ("push", "reader", False),
        ("delete", "admin", True),
        ("delete", "writer", False),
        ("rename", "writer", True),
        ("rename", "reader", False),
    ]
    for action, role, expected in cases:
        req = {"id": "w", "action": action, "role": role, "namespace": "prod/app", "target": "prod/app2"}
        decision = authorize(req, POLICY, NOW)
        assert decision["allowed"] is expected
        assert len(decision["audit"]) == 1, action
        assert decision["audit"][0]["action"] == action
        assert decision["audit"][0]["role"] == parse_role(role)["name"]


def test_rejected_reads_leave_no_audit_but_allowed_reads_do():
    denied = authorize(
        {"id": "r", "action": "pull", "role": "anonymous", "namespace": "prod/app"},
        POLICY,
        NOW,
    )
    assert denied["allowed"] is False and denied["audit"] == []

    allowed = authorize(
        {"id": "r", "action": "pull", "role": "reader", "namespace": "prod/app"},
        POLICY,
        NOW,
    )
    assert allowed["allowed"] is True and len(allowed["audit"]) == 1


# --- policy validation -----------------------------------------------------

def test_validate_policy_reports_codes_in_stable_order():
    assert validate_policy(POLICY) == []
    problems = validate_policy({})
    assert problems == [
        "role_missing:admin",
        "role_missing:writer",
        "role_missing:reader",
        "audit_missing",
    ]
    problems = validate_policy({"anonymous": True})
    assert problems == [
        "role_missing:admin",
        "role_missing:writer",
        "role_missing:reader",
        "anonymous_default_on",
        "audit_missing",
    ]

    on_and_audited = validate_policy(
        {"roles": POLICY["roles"], "anonymous": True, "audit": True}
    )
    assert on_and_audited == ["anonymous_default_on"]
