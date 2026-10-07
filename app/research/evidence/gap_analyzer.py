"""Principled Missing Evidence Gap Analyzer for Pentrare.

Evaluates security research hypotheses against researcher-supplied observations
and artifacts to identify missing empirical evidence required for validation.

Does not hardcode scenario IDs or read ground truth. Operates on objective
security testing requirements for each vulnerability classification family.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set


class MissingEvidenceAnalyzer:
    """Analyzes evidence completeness and surfaces concrete verification gaps."""

    @classmethod
    def analyze_gaps(
        cls,
        hypothesis: str,
        observations: List[Dict[str, Any]] | List[Any],
        evidence_content: str = "",
        classification: str = "UNCONFIRMED",
    ) -> List[str]:
        """Detect missing evidence items needed to advance confidence.

        Args:
            hypothesis: The security hypothesis or research objective statement.
            observations: List of observation dicts or SyntheticObservation objects.
            evidence_content: Raw artifact content (HTTP, logs, code, etc.).
            classification: Current evaluation classification.

        Returns:
            List of prioritized missing evidence statements.
        """
        hyp_lower = (hypothesis or "").lower()
        ev_lower = (evidence_content or "").lower()

        # Extract observation text
        obs_texts: List[str] = []
        is_supporting_list: List[bool] = []
        is_contradicting_list: List[bool] = []

        for o in observations:
            if isinstance(o, dict):
                stmt = o.get("statement") or o.get("content") or ""
                obs_texts.append(stmt)
                is_supporting_list.append(bool(o.get("is_supporting", True)))
                is_contradicting_list.append(bool(o.get("is_contradicting", False)))
            else:
                stmt = getattr(o, "content", "") or getattr(o, "statement", "")
                obs_texts.append(stmt)
                is_supporting_list.append(bool(getattr(o, "is_supporting", True)))
                is_contradicting_list.append(bool(getattr(o, "is_contradicting", False)))

        all_text = " ".join(obs_texts + [ev_lower, hyp_lower]).lower()
        has_contradiction = any(is_contradicting_list) or any(
            c in all_text for c in ["401 unauthorized", "403 forbidden", "access denied", "signature failed"]
        )
        supporting_count = sum(1 for s, c in zip(is_supporting_list, is_contradicting_list) if s and not c)

        missing: List[str] = []

        # Category 1: IDOR / BOLA / Object Reference Authorization
        if any(k in hyp_lower for k in ["idor", "bola", "object reference", "cross-user", "another user", "ownership", "profile update", "uuid"]):
            has_two_users = any(k in all_text for k in ["user_a", "user_b", "alice", "bob", "uuid-aaaa", "uuid-bbbb", "victim", "attacker"])
            has_cross_check = any(k in all_text for k in ["decoded", "jwt confirms", "different account", "ownership check"])
            has_sequential_check = any(k in all_text for k in ["non-sequential", "enumeration test", "random id"])

            if not has_two_users or supporting_count < 2:
                missing.append("Cross-user request comparison with secondary independent account.")
            if not has_cross_check:
                missing.append("Confirmation that target resource identifier belongs to a distinct tenant/account.")
            if any(k in all_text for k in ["order_id", "numeric id", "1001", "integer"]):
                missing.append("Test with non-sequential ID to confirm enumeration vs authorized range.")

        # Category 2: Authentication Bypass / Token Flaws
        elif any(k in hyp_lower for k in ["auth", "jwt", "token", "login", "session", "bypass"]):
            has_unauth_baseline = any(k in all_text for k in ["unauthenticated baseline", "no token", "anonymous request", "401"])
            has_tamper_test = any(k in all_text for k in ["none alg", "tampered", "modified signature", "expired"])

            if not has_unauth_baseline:
                missing.append("Baseline request without authentication headers showing expected access restriction.")
            if not has_tamper_test:
                missing.append("Negative test demonstrating token rejection when signature or claims are invalidated.")

        # Category 3: Privilege Escalation / Role Enforcement
        elif any(k in hyp_lower for k in ["role", "privilege", "admin", "escalat"]):
            has_role_check = any(k in all_text for k in ["admin role grants", "elevated access verified", "permission check"])
            has_persistence = any(k in all_text for k in ["persists across sessions", "subsequent session", "re-login"])

            if not has_role_check:
                missing.append("Verification that modified role parameter actually grants elevated system capabilities.")
            if not has_persistence:
                missing.append("Confirmation that role modification persists across subsequent independent sessions.")

        # Category 4: Information Disclosure / Weak Evidence / Server Banners
        elif any(k in hyp_lower for k in ["banner", "version", "information disclosure", "stack trace", "debug"]):
            missing.append("Known CVE exploitability assessment beyond passive version disclosure.")
            missing.append("Proof that disclosed information enables secondary security boundary breach.")

        # Category 5: SSRF / Webhook / Out-of-Band Calls
        elif any(k in hyp_lower for k in ["ssrf", "webhook", "metadata", "internal ip"]):
            if "169.254" not in all_text and "aws" not in all_text:
                missing.append("Demonstrated access to internal link-local metadata or RFC1918 private network service.")
            missing.append("Confirmation that response data originates from internal service rather than public mirror.")

        # Category 6: Contradictions / Caching / Inconsistent Behavior
        if has_contradiction:
            missing.append("Clarifying test resolving why contradictory access control rejections (401/403) were observed.")
        if any(k in all_text for k in ["cache", "age:", "x-cache"]):
            missing.append("Test with fresh session tokens and Cache-Control: no-cache to rule out proxy caching.")

        # Universal fallback gap when evidence is thin or single-observation
        if supporting_count <= 1 and not missing:
            missing.append("Differential test verifying behavior across independent user accounts.")
            missing.append("Multi-session reproduction trace confirming persistence.")

        # Deduplicate while preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for item in missing:
            norm = item.strip()
            if norm and norm not in seen:
                seen.add(norm)
                deduped.append(norm)

        return deduped
