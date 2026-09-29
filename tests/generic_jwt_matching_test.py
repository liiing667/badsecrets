"""Regression tests for structure-based JWT matching.

Reproduces the two pipeline pain points that motivated the rework:

- False positives: short random strings and base64'd JSON fragments that the
  legacy "eyJ" prefix regex flagged as JWTs.
- False negatives: real JWTs whose base64url prefix differs from "eyJ" because
  the header JSON is not compact ("{ " -> "eyA", "{\\n" -> "ewo", "{\\t" ->
  "ewk"), or that arrive with an RFC 6750 "Bearer " scheme prefix.

Also pins confidence-level reporting and scan determinism.
"""

import re

import pytest

from badsecrets import modules_loaded
from badsecrets.base import check_all_modules

Generic_JWT = modules_loaded["generic_jwt"]

# The legacy prefix-based identify_regex, kept here to prove the FP/FN samples
# below genuinely reproduce the old behavior.
OLD_PREFIX_REGEX = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")

# Real HS256 JWTs (secret "1234", payload {"sub":"1234567890",...}) whose header
# JSON is not compact, so the base64url prefix is not "eyJ".
JWT_COMPACT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SP0R2USEDHqPV7mcIK08ZAs4WtPMQ0NdMHuSD8tnWOw"
# header: { "alg": "HS256", "typ": "JWT" }
JWT_SPACE_HEADER = "eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJKV1QiIH0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.uiFslnfKxQSZgv97ZYnKRqk_MpAV0Ve0okdp95n3AL0"
# header: {\n"alg": "HS256",\n"typ": "JWT"\n}
JWT_NEWLINE_HEADER = "ewoiYWxnIjogIkhTMjU2IiwKInR5cCI6ICJKV1QiCn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1ZyK6YuqbvneziwFAjAcX7j8YZyLHqtnFAVeO6uUqKY"
# header: {\t"alg":"HS256","typ":"JWT"}
JWT_TAB_HEADER = "ewkiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xvESQYV258kEsRH21BpHqYbfVSQw23n4ixC2PPbJ6k0"

PREFIX_VARIANT_JWTS = [
    JWT_SPACE_HEADER,
    JWT_NEWLINE_HEADER,
    JWT_TAB_HEADER,
    f"Bearer {JWT_COMPACT}",
]

# Short random strings / fragments that the legacy prefix regex flagged.
FALSE_POSITIVE_SAMPLES = [
    "eyJ..",
    "eyJh.YQ.YQ",
    "eyJx.1a2b.3c",
    "eyJhbGciOiJIUzI1NiJ9..",
]


@pytest.mark.parametrize("sample", FALSE_POSITIVE_SAMPLES)
def test_former_false_positives_rejected(sample):
    # Reproduce the old behavior: these all matched the prefix regex.
    assert OLD_PREFIX_REGEX.match(sample)
    # Structural validation rejects them: no decodable JSON header.
    assert not Generic_JWT.identify(sample)
    assert Generic_JWT.identify_confidence(sample) is None
    r = check_all_modules(sample)
    jwt_hits = [x for x in (r or []) if x["detecting_module"] == "Generic_JWT"]
    assert not jwt_hits


@pytest.mark.parametrize("token", PREFIX_VARIANT_JWTS)
def test_prefix_variant_jwts_no_longer_missed(token):
    # Reproduce the old behavior: none of these start with the "eyJ" prefix.
    assert not OLD_PREFIX_REGEX.match(token)
    x = Generic_JWT()
    assert x.identify(token)
    assert x.identify_confidence(token) == "high"
    found = x.check_secret(token)
    assert found
    assert found["secret"] == "1234"


def test_prefix_variant_jwt_body_carve():
    body = f"<html><body><p>token: {JWT_NEWLINE_HEADER}</p></body></html>"
    r = Generic_JWT().carve(body=body)
    assert r
    assert r[0]["type"] == "SecretFound"
    assert r[0]["secret"] == "1234"
    assert r[0]["confidence"] == "high"


def test_confidence_levels():
    x = Generic_JWT()
    # Fully valid structure: JSON header with alg + JSON payload
    assert x.identify_confidence(JWT_COMPACT) == "high"
    assert x.identify_confidence(f"Bearer {JWT_COMPACT}") == "high"
    # alg=none with empty signature is still structurally complete
    assert x.identify_confidence("eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.") == "high"
    # JSON object header without "alg": JWT-shaped but unverifiable as one
    assert x.identify_confidence("eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA") == "low"
    # base64url('{"user":"a"}'): a JSON fragment, not a JWT header
    assert x.identify_confidence("eyJ1c2VyIjoiYSJ9.e30.e30") == "low"
    # alg present but payload is not JSON
    assert x.identify_confidence("eyJhbGciOiJIUzI1NiJ9.aGVsbG8.eA") == "low"


def test_results_carry_confidence():
    # Cracked secret -> high; shape-only match -> low
    r = check_all_modules(JWT_SPACE_HEADER)
    jwt_results = [x for x in r if x["detecting_module"] == "Generic_JWT"]
    assert len(jwt_results) == 1
    assert jwt_results[0]["type"] == "SecretFound"
    assert jwt_results[0]["confidence"] == "high"

    # Structurally complete JWT whose secret is not in the wordlist -> high
    r = check_all_modules(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJhZFNpZ25hdHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.S_8lg9Pzezv8JhXT3cppPZcz046cFM8H1o1GJYYAAAA"
    )
    jwt_results = [x for x in r if x["detecting_module"] == "Generic_JWT"]
    assert len(jwt_results) == 1
    assert jwt_results[0]["type"] == "IdentifyOnly"
    assert jwt_results[0]["confidence"] == "high"

    # JWT-shaped but no "alg" in the header -> low
    r = check_all_modules("eyJ1c2VyIjoiYSJ9.e30.e30")
    jwt_results = [x for x in r if x["detecting_module"] == "Generic_JWT"]
    assert len(jwt_results) == 1
    assert jwt_results[0]["type"] == "IdentifyOnly"
    assert jwt_results[0]["confidence"] == "low"


def test_junk_shape_before_real_jwt_still_found():
    # "1.2.3" and "Telerik.Web.UI" match the 3-segment shape; the real token
    # comes later. Every candidate must be validated, not just the first.
    body = f"<html><body><p>version 1.2.3</p><p>Telerik.Web.UI</p><p>{JWT_COMPACT}</p></body></html>"
    r = Generic_JWT().carve(body=body)
    assert r
    assert r[0]["type"] == "SecretFound"
    assert r[0]["secret"] == "1234"


def test_repeated_scans_are_stable():
    body = (
        f"<html><body><p>release 1.2.3 notes</p><p>{JWT_COMPACT}</p>"
        f"<p>foo.bar.baz</p><p>{JWT_SPACE_HEADER}</p><p>{JWT_COMPACT}</p></body></html>"
    )
    first = Generic_JWT().carve(body=body)
    assert [r["type"] for r in first] == ["SecretFound", "SecretFound"]
    for _ in range(5):
        assert Generic_JWT().carve(body=body) == first

    first_manual = check_all_modules(JWT_COMPACT)
    for _ in range(5):
        assert check_all_modules(JWT_COMPACT) == first_manual


def test_identify_tolerates_non_string_input():
    assert not Generic_JWT.identify(None)
    assert not Generic_JWT.identify(1234)
