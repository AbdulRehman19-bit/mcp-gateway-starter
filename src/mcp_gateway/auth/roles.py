"""Scope -> role resolution (pure). The role comes only from validated token scopes.

Why deny on ambiguity: roles are not strictly ordered (analyst and approver have different
tools, analyst and operator see different tables), so "pick the least privileged" is a guess.
A token that maps to more than one role is refused; the IdP should issue one role's scope.
"""

from dataclasses import dataclass

from mcp_gateway.policy.models import Policy


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str
    scopes: frozenset[str]


def resolve_role(policy: Policy, subject: str, scopes: frozenset[str]) -> Identity | None:
    roles = {policy.scope_to_role[s] for s in scopes if s in policy.scope_to_role}
    if len(roles) != 1:  # none mapped, or ambiguous: fail closed
        return None
    (role,) = roles
    if role not in policy.roles:
        return None
    return Identity(subject=subject, role=role, scopes=scopes)
