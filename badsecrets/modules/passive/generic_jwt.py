import re
import logging
import warnings
import jwt as j
import json
import base64
from badsecrets.base import BadsecretsBase

log = logging.getLogger(__name__)

# XMLDSIG Translation Table

XMLDSIG_table = {
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256": "HS256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384": "HS384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512": "HS512",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RS256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "RS384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RS512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ES256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ES384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ES512",
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": "PS256",
    "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": "PS384",
    "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": "PS512",
}


class Generic_JWT(BadsecretsBase):
    # Structural shape of a JWS compact serialization: three base64url segments.
    # Kept as a class attribute for consistency with other modules, but the real
    # matching logic lives in identify_confidence() below, which validates the
    # decoded structure instead of relying on the "eyJ" prefix. The prefix is
    # just base64url('{"...') and varies with JSON formatting ("{ " -> "eyA",
    # "{\n" -> "ewo", "{\t" -> "ewk"), so prefix matching both false-positives
    # on any base64'd JSON fragment and false-negatives on non-compact headers.
    identify_regex = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
    yara_carve_pattern = r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    description = {"product": "JSON Web Token (JWT)", "secret": "HMAC/RSA Key", "severity": "HIGH"}

    _bearer_prefix_regex = re.compile(r"^Bearer\s+(\S+)$", re.IGNORECASE)
    _base64url_segment_regex = re.compile(r"^[A-Za-z0-9_-]+$")

    @classmethod
    def _normalize_token(cls, product):
        """Strip surrounding whitespace and an optional RFC 6750 'Bearer ' scheme prefix."""
        token = product.strip()
        m = cls._bearer_prefix_regex.match(token)
        if m:
            token = m.group(1)
        return token

    @staticmethod
    def _decode_json_segment(segment):
        """base64url-decode a JWT segment and JSON-parse it. Returns the decoded
        object, or None if the segment is not valid base64url-encoded JSON."""
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            return json.loads(decoded)
        except Exception:
            return None

    @classmethod
    def identify_confidence(cls, product):
        """Structurally validate a JWT candidate.

        Returns:
            "high" - three base64url segments; header decodes to a JSON object
                     containing "alg"; payload decodes to a JSON object.
            "low"  - JWT-shaped (three segments, JSON object header) but missing
                     "alg" or carrying a non-JSON payload.
            None   - not a JWT.
        """
        if not isinstance(product, str):
            return None
        parts = cls._normalize_token(product).split(".")
        if len(parts) != 3:
            return None
        header_segment, payload_segment, signature_segment = parts
        # Header and payload must be non-empty; the signature may be empty (alg=none)
        if not header_segment or not payload_segment:
            return None
        for segment in (header_segment, payload_segment, signature_segment):
            if segment and not cls._base64url_segment_regex.match(segment):
                return None
        header = cls._decode_json_segment(header_segment)
        if not isinstance(header, dict):
            return None
        payload = cls._decode_json_segment(payload_segment)
        if "alg" in header:
            return "high" if isinstance(payload, dict) else "low"
        return "low"

    @staticmethod
    def swap_algorithm(jwt, algorithm):
        header = j.get_unverified_header(jwt)
        header["alg"] = algorithm
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        )
        _, payload, signature = jwt.split(".")
        new_jwt = f"{header_encoded}.{payload}.{signature}"
        return new_jwt

    def carve_regex(self):
        return re.compile(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)")

    def _carve_body(self, body, cookies, headers, **kwargs):
        """Carve JWTs from body text.

        Overrides the base implementation (which only inspects the first regex
        match) so every candidate is structurally validated in order. This keeps
        results stable when shape-like noise (e.g. "1.2.3") appears before a real
        token, and deduplicates repeated occurrences of the same token.
        """
        results = []
        seen = set()
        for s in re.finditer(self.carve_regex(), body):
            candidate = s.groups()[0]
            if candidate in seen:
                continue
            seen.add(candidate)
            if not self.identify(candidate):
                continue
            r = self.check_secret(candidate)
            if r:
                r["type"] = "SecretFound"
            else:
                r = {"type": "IdentifyOnly"}
                r["hashcat"] = self._safe_hashcat(candidate)
            r["product"] = candidate
            r["location"] = "body"
            results.append(r)
        return results

    def jwtVerify(self, JWT, key, algorithm):
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=j.warnings.InsecureKeyLengthWarning)
                r = j.decode(
                    JWT,
                    key,
                    algorithms=[algorithm],
                    options={"verify_exp": False, "verify_aud": False, "verify_nbf": False},
                )
            return r
        except j.exceptions.InvalidSignatureError:
            return None
        except j.exceptions.InvalidKeyError as e:
            log.debug(f"Invalid key for JWT verification ({algorithm}): {e}")
            return None

    def jwtLoad(self, JWT):
        JWT = self._normalize_token(JWT)
        try:
            jwt_headers = j.get_unverified_header(JWT)
        # if the JWT is not well formed, stop here
        except j.exceptions.DecodeError:
            return (None, None, None)
        try:
            algorithm = jwt_headers["alg"]

        # It could be a JWT-like token that is actually a different format, for example a flask cookie
        except KeyError:
            return (None, None, None)

        if algorithm in XMLDSIG_table:
            algorithm = XMLDSIG_table[algorithm]
            JWT = self.swap_algorithm(JWT, algorithm)

        return jwt_headers, algorithm, JWT

    def get_hashcat_commands(self, JWT, *args):
        jwt_headers, algorithm, JWT = self.jwtLoad(JWT)
        if jwt_headers and algorithm and JWT:
            if algorithm[0].lower() != "h":
                return None

            return [
                {
                    "command": f"hashcat -m 16500 -a 0 {JWT}  <dictionary_file>",
                    "description": f"JSON Web Token (JWT) Algorithm: {algorithm}",
                }
            ]

    def check_secret(self, JWT):
        if not self.identify(JWT):
            return None

        jwt_headers, algorithm, JWT = self.jwtLoad(JWT)
        if not jwt_headers or not algorithm or not JWT:
            return None

        if algorithm[0].lower() == "h":
            for l in self.load_resources(["jwt_secrets.txt", "top_100000_passwords.txt"]):
                key = l.strip()

                r = self.jwtVerify(JWT, key, algorithm)
                if r:
                    r["jwt_headers"] = jwt_headers
                    return {"secret": key, "details": r}

        elif algorithm[0].lower() == "r":
            for l in self.load_resources(["jwt_rsakeys_public.txt"]):
                private_key_name = l.split(":")[0]
                public_key = f"{l.split(':')[1]}".rstrip().encode().replace(b"\\n", b"\n")
                r = self.jwtVerify(JWT, public_key, algorithm)
                if r:
                    r["jwt_headers"] = jwt_headers
                    return {"secret": f"Private key Name: {private_key_name}", "details": r}

        return None
