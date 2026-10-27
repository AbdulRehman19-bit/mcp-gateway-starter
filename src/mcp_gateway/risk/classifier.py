"""Risk classification (pure). Unknown means high: a tool we cannot place never skips approval."""

from mcp_gateway.policy.models import DESTRUCTIVE_TOOLS, Policy, RiskTier


def classify(policy: Policy, tool: str) -> RiskTier:
    if tool in DESTRUCTIVE_TOOLS:
        return "high"  # a hard floor in code, whatever the policy file says
    return policy.risk.tier_of(tool) or "high"


def needs_approval(policy: Policy, role: str, tool: str) -> bool:
    """High risk always needs a human; a role may additionally require it for lower tiers.

    Unknown role: approval required (it will be denied earlier anyway; this is the safe default).
    """
    rp = policy.roles.get(role)
    if rp is None:
        return True
    return classify(policy, tool) == "high" or tool in rp.approval_required
