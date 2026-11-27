"""Permission checks for a container registry.

The module models a small role based policy layer for a registry service.
Roles resolve to push, pull and delete flags, namespaces inherit from a
parent namespace, and write attempts are expected to leave an audit record
behind so that an operator can reconstruct who changed what.
"""

from __future__ import annotations

from datetime import datetime

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

FLAGS = ("push", "pull", "delete")
WRITE_ACTIONS = ("push", "delete", "rename")
REQUIRED_ROLES = ("admin", "writer", "reader")

ROLE_TABLE = {
    "admin": {"push": True, "pull": True, "delete": True},
    "writer": {"push": True, "pull": True, "delete": False},
    "reader": {"push": False, "pull": True, "delete": False},
}

ROLE_ALIASES = {
    "admin": "admin",
    "owner": "admin",
    "root": "admin",
    "writer": "writer",
    "developer": "writer",
    "publisher": "writer",
    "reader": "reader",
    "viewer": "reader",
    "readonly": "reader",
}


def parse_role(role):
    """Resolve a role name or role mapping into a permission mapping.

    The result always carries the keys name, push, pull, delete and scope.
    An empty role, the name anonymous and the name guest all describe an
    unauthenticated caller.  Names that the table does not know fall back
    to a deny everything mapping instead of raising.
    """
    if isinstance(role, dict):
        name = str(role.get("name") or "custom").strip().lower()
        return {
            "name": name,
            "push": bool(role.get("push")),
            "pull": bool(role.get("pull")),
            "delete": bool(role.get("delete")),
            "scope": [str(item) for item in (role.get("scope") or [])],
        }

    name = str(role or "").strip().lower()
    if not name or name in ("anonymous", "guest"):
        return {
            "name": "anonymous",
            "push": False,
            "pull": False,
            "delete": False,
            "scope": [],
        }

    canonical = ROLE_ALIASES.get(name)
    if canonical is None:
        return {
            "name": "unknown",
            "push": False,
            "pull": False,
            "delete": False,
            "scope": [],
        }

    table = ROLE_TABLE[canonical]
    return {
        "name": canonical,
        "push": table["push"],
        "pull": table["pull"],
        "delete": table["delete"],
        "scope": [],
    }


def _namespace_name(namespace):
    """Return the canonical text form of a namespace name or mapping."""
    if isinstance(namespace, dict):
        namespace = namespace.get("name")
    text = str(namespace or "").strip().strip("/").lower()
    return text


def _scope_allows(scope, namespace):
    """Return True when a role scope covers the namespace."""
    if not scope:
        return True
    name = _namespace_name(namespace)
    for entry in scope:
        entry = _namespace_name(entry)
        if entry and (name == entry or name.startswith(entry + "/")):
            return True
    return False


def check_push(role, namespace):
    """Return True when the role may push to the namespace.

    Push requires the push flag.  A role that carries a scope is limited to
    the listed namespaces and their children.
    """
    perms = parse_role(role)
    if not perms["push"]:
        return False
    return _scope_allows(perms.get("scope"), namespace)


def check_pull(role, namespace, anonymous):
    """Return True when the role may pull from the namespace.

    Anonymous callers are served only when anonymous access was switched
    on explicitly; the flag is tri-state and None means the setting was
    never configured, which behaves like switched off.
    """
    perms = parse_role(role)
    if perms["name"] == "anonymous":
        return anonymous is True
    if not perms["pull"]:
        return False
    return _scope_allows(perms.get("scope"), namespace)


def _timestamp(now):
    """Return True when now is a usable timestamp."""
    if now is None or now == "":
        return False
    if isinstance(now, datetime):
        return True
    try:
        datetime.fromisoformat(str(now).replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def check_delete(role, now):
    """Return True when the role may delete an image at the given time.

    Only administrators may delete, and a delete attempt must carry a
    timestamp that can be parsed so the audit trail stays reconstructable.
    """
    if not _timestamp(now):
        return False
    perms = parse_role(role)
    return perms["name"] == "admin" and perms["delete"]


def _namespace_view(namespace):
    """Normalise a namespace mapping into name, parent and permission flags."""
    if isinstance(namespace, dict):
        return {
            "name": _namespace_name(namespace),
            "parent": _namespace_name(namespace.get("parent")) or None,
            "push": bool(namespace.get("push")),
            "pull": bool(namespace.get("pull")),
            "delete": bool(namespace.get("delete")),
        }
    return {
        "name": _namespace_name(namespace),
        "parent": None,
        "push": False,
        "pull": False,
        "delete": False,
    }


def check_inherit(namespace, parent):
    """Return True when a namespace inherits consistently from its parent.

    A child namespace may tighten what it inherits but it may never grant
    push, pull or delete that the parent namespace does not grant.  When
    parent is None the namespace must be a root of its own tree.
    """
    child = _namespace_view(namespace)
    if parent is None:
        return child["parent"] in (None, "")
    par = _namespace_view(parent)
    if child["parent"] != par["name"]:
        return False
    # A child may only tighten its parent: every flag the child grants must
    # also be granted by the parent.  Any flag granted only by the child
    # widens the permission boundary and makes the tree inconsistent.
    for flag in FLAGS:
        if child[flag] and not par[flag]:
            return False
    return True


def _timestamp_text(now):
    """Render a timestamp for an audit record."""
    if isinstance(now, datetime):
        return now.isoformat()
    return str(now or "")


def _audit_entry(request, action, perms, allowed, now):
    """Build the audit record for one write attempt."""
    target = request.get("target")
    return {
        "action": action,
        "namespace": _namespace_name(request.get("namespace")),
        "target": _namespace_name(target) if target else None,
        "role": perms["name"],
        "allowed": bool(allowed),
        "at": _timestamp_text(now),
    }


def _decision(request, perms, allowed, reason, audit):
    """Build the decision document returned by authorize."""
    return {
        "allowed": bool(allowed),
        "reason": reason,
        "role": perms["name"],
        "request_id": request.get("id"),
        "namespace": _namespace_name(request.get("namespace")),
        "audit": list(audit),
    }


def authorize(request, policy, now):
    """Decide one registry request and attach its audit trail.

    Every write attempt, allowed or rejected, produces exactly one audit
    record.  A successful read is audited as well, while a rejected read
    leaves no trace because it changed nothing.
    """
    req = dict(request or {})
    policy = dict(policy or {})
    action = str(req.get("action") or "").strip().lower()
    role = req.get("role")
    namespace = req.get("namespace")
    perms = parse_role(role)

    anonymous = req.get("anonymous")
    if anonymous is None:
        anonymous = policy.get("anonymous")

    if action == "push":
        allowed = check_push(role, namespace)
        reason = "push_allowed" if allowed else "push_denied"
    elif action == "pull":
        allowed = check_pull(role, namespace, anonymous)
        reason = "pull_allowed" if allowed else "pull_denied"
    elif action == "delete":
        allowed = check_delete(role, now)
        reason = "delete_allowed" if allowed else "delete_denied"
    elif action == "rename":
        target = req.get("target")
        if not target:
            allowed = False
            reason = "rename_target_missing"
        else:
            # A rename moves an image out of the source namespace and into
            # the target namespace, so both sides have to authorize the
            # write independently; checking only the target would let a
            # caller escape a source namespace they cannot write to.
            allowed = check_push(role, namespace) and check_push(role, target)
            reason = "rename_allowed" if allowed else "rename_denied"
    else:
        allowed = False
        reason = "unknown_action"

    audit = []
    if action in WRITE_ACTIONS or allowed:
        audit.append(_audit_entry(req, action, perms, allowed, now))
    return _decision(req, perms, allowed, reason, audit)


def validate_policy(policy):
    """Return the list of problems found in a policy document.

    The checks cover the role table, the anonymous default and the audit
    switch.  Problem codes are reported in a stable order: missing roles
    first, then the anonymous default, then the audit switch.
    """
    problems = []
    policy = policy or {}
    roles = policy.get("roles") or {}
    if not isinstance(roles, dict):
        problems.append("roles_invalid")
        roles = {}
    for name in REQUIRED_ROLES:
        if name not in roles:
            problems.append("role_missing:" + name)
    if policy.get("anonymous") is True:
        problems.append("anonymous_default_on")
    if not policy.get("audit"):
        problems.append("audit_missing")
    return problems


def registry_batch(requests, policy, now):
    """Decide a list of requests and report the aggregate outcome.

    Each request is decided on its own so that the order of the list and
    the outcome of a neighbour can never change a decision.
    """
    results = []
    for index, request in enumerate(requests or []):
        item = dict(request or {})
        outcome = authorize(item, policy, now)
        outcome["index"] = index
        results.append(outcome)
    return {
        "total": len(results),
        "allowed": sum(1 for item in results if item["allowed"]),
        "results": results,
    }