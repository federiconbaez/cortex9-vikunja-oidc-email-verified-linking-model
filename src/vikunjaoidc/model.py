"""Offline model of Vikunja OIDC email-fallback linking (CVE-2026-62367).

Ports fallbackSearchUsers from pkg/modules/auth/openid/openid.go at parent
be36c11e (pre) and fix 7854f272 (post). Diff lines 39-65 of
diffs/CVE-2026-62367_vikunja_7854f2729ab7.diff.

Also ports the boolish JSON decoder for email_verified (diff lines 9-27).
No network, no real OIDC provider: a local in-memory user store decides
whether a claim set would link to an existing local account.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field


def decode_boolish(raw) -> bool:
    """Port of boolish.UnmarshalJSON (post). Pre has no email_verified field."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw == "true" or raw == "1"
    return False


@dataclass
class Provider:
    email_fallback: bool = False
    username_fallback: bool = False


@dataclass
class Claims:
    email: str = ""
    email_verified: bool = False
    preferred_username: str = ""


@dataclass
class IdToken:
    subject: str = ""
    issuer: str = "https://idp.example"


@dataclass
class LocalUser:
    id: int
    email: str
    username: str
    issuer: str = "local"


def fallback_search_pre(cl: Claims, provider: Provider, idt: IdToken) -> list[dict]:
    """pre: EmailFallback alone is enough to put email into the lookup."""
    fallback_email = ""
    if provider.email_fallback:
        fallback_email = cl.email
    searches: list[dict] = []
    if provider.username_fallback:
        if idt.subject:
            searches.append({"issuer": "local", "username": idt.subject, "email": fallback_email})
        preferred = cl.preferred_username.replace(" ", "-")
        if preferred and preferred != idt.subject:
            searches.append({"issuer": "local", "username": preferred, "email": fallback_email})
    if len(searches) == 0 and cl.email != "":
        searches.append({"issuer": "local", "email": cl.email})
    return searches


def fallback_search_post(cl: Claims, provider: Provider, idt: IdToken) -> list[dict]:
    """post: requires EmailFallback AND email_verified."""
    email_fallback_allowed = provider.email_fallback and cl.email_verified
    fallback_email = ""
    if email_fallback_allowed:
        fallback_email = cl.email
    searches: list[dict] = []
    if provider.username_fallback:
        if idt.subject:
            searches.append({"issuer": "local", "username": idt.subject, "email": fallback_email})
        preferred = cl.preferred_username.replace(" ", "-")
        if preferred and preferred != idt.subject:
            searches.append({"issuer": "local", "username": preferred, "email": fallback_email})
    if len(searches) == 0 and email_fallback_allowed and cl.email != "":
        searches.append({"issuer": "local", "email": cl.email})
    return searches


USERS = [
    LocalUser(11, "user11@example.com", "user11"),
    LocalUser(22, "alice@example.com", "alice"),
]


def link(searches: list[dict]) -> str:
    """Return 'LINKED:<id>' if a search matches a local user, else 'NEW'.

    Mirrors GetUserWithEmail ANDing non-zero fields: email-only matches by
    email; username(+email) matches when username equals and email is empty
    or equals.
    """
    for s in searches:
        if s.get("issuer") != "local":
            continue
        for u in USERS:
            if "username" in s and s["username"]:
                if s["username"] != u.username:
                    continue
                if s.get("email") and s["email"] != u.email:
                    continue
                return f"LINKED:{u.id}"
            if s.get("email") and s["email"] == u.email:
                return f"LINKED:{u.id}"
    return "NEW"


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    description: str
    claims: Claims
    provider: Provider
    idt: IdToken
    pre: str
    post: str


CASES = [
    Case("p01_unverified_email_fallback", "pos",
         "EmailFallback + email_verified=false + victim email (GHSA test)",
         Claims("user11@example.com", False, "attackerUser"),
         Provider(email_fallback=True), IdToken("attacker-subject"),
         "LINKED:11", "NEW"),
    Case("p02_missing_verified_claim", "pos",
         "EmailFallback + email_verified default false (absent claim)",
         Claims("user11@example.com", False, ""),
         Provider(email_fallback=True), IdToken("attacker-subject"),
         "LINKED:11", "NEW"),
    Case("p03_string_false", "pos",
         "email_verified JSON string 'false' (boolish)",
         Claims("user11@example.com", decode_boolish("false"), ""),
         Provider(email_fallback=True), IdToken("x"),
         "LINKED:11", "NEW"),
    Case("n01_verified_true", "neg",
         "email_verified=true links under both (GHSA positive control)",
         Claims("user11@example.com", True, ""),
         Provider(email_fallback=True), IdToken("attacker-subject"),
         "LINKED:11", "LINKED:11"),
    Case("n02_string_true", "neg",
         "email_verified JSON string 'true'",
         Claims("alice@example.com", decode_boolish("true"), ""),
         Provider(email_fallback=True), IdToken("y"),
         "LINKED:22", "LINKED:22"),
    Case("n03_fallback_disabled", "neg",
         "EmailFallback=false: no email-only search",
         Claims("user11@example.com", False, "attackerUser"),
         Provider(email_fallback=False), IdToken("attacker-subject"),
         "NEW", "NEW"),
    Case("n04_empty_email", "neg",
         "empty email cannot link",
         Claims("", True, "attackerUser"),
         Provider(email_fallback=True), IdToken("z"),
         "NEW", "NEW"),
    Case("n05_unknown_email_verified", "neg",
         "verified email of a non-existent user → NEW under both",
         Claims("nobody@example.com", True, ""),
         Provider(email_fallback=True), IdToken("z"),
         "NEW", "NEW"),
]


def evaluate_case(case: Case) -> dict:
    # Caller gate in getOrCreateUser: only invoke fallback when at least one
    # fallback flag is enabled (openid.go around the call site).
    def outcome(side: str) -> str:
        p = case.provider
        if not (p.email_fallback or p.username_fallback):
            return "NEW"
        searches = (fallback_search_pre if side == "pre" else fallback_search_post)(
            case.claims, p, case.idt
        )
        return link(searches)
    pre = outcome("pre")
    post = outcome("post")
    ok = pre == case.pre and post == case.post
    flips = case.kind == "pos" and pre.startswith("LINKED:") and post == "NEW"
    return {
        "id": case.id, "kind": case.kind, "description": case.description,
        "pre": pre, "post": post, "expected_pre": case.pre, "expected_post": case.post,
        "ok": ok, "flips": flips,
    }
