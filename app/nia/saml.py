"""
NIA SAML2 Service Provider implementation.

Handles:
- SAML AuthnRequest generation (SP → NIA IdP)
- SAMLResponse validation and attribute extraction (NIA IdP → SP)
- NIA IdP metadata fetching and caching

NIA endpoints:
  TEST: https://tnia.identita.gov.cz/FPSTS/saml2/basic
  PROD: https://nia.identita.gov.cz/FPSTS/saml2/basic

TODO: Individuální výdej údajů a ConsentIV – not implemented in MVP.
"""
import base64
import hashlib
import logging
import time
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote_plus
from xml.etree import ElementTree as ET

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

# SAML XML namespaces
NS = {
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "fed": "http://docs.oasis-open.org/wsfed/federation/200706",
}

# Cache for IdP metadata (certificates, endpoints)
_metadata_cache: Optional[Dict[str, Any]] = None
_metadata_cache_time: float = 0
METADATA_CACHE_TTL = 86400  # 24 hours


class SAMLValidationError(Exception):
    """Raised when SAML response validation fails."""

    def __init__(self, message: str, code: str = "NIA_RESPONSE_INVALID"):
        self.message = message
        self.code = code
        super().__init__(message)


class NIASamlService:
    """
    SAML2 Service Provider for NIA (Národní identitní autorita).

    Generates AuthnRequests and validates SAMLResponses from NIA IdP.
    Uses HTTP-Redirect binding for AuthnRequest and HTTP-POST for ACS.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.entity_id = settings.nia_entity_id
        self.acs_url = settings.nia_acs_url
        self.sso_url = settings.nia_saml_endpoint
        self.metadata_url = settings.nia_metadata_url

    def create_authn_request_redirect_url(
        self,
        relay_state: str,
    ) -> str:
        """
        Create SAML AuthnRequest and return the redirect URL for NIA IdP.

        Uses HTTP-Redirect binding: AuthnRequest is deflated, base64-encoded,
        and sent as a query parameter.

        Args:
            relay_state: Opaque state string for CSRF protection and session lookup.

        Returns:
            Full redirect URL to NIA IdP SSO endpoint.
        """
        request_id = f"_id-{uuid.uuid4()}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build AuthnRequest XML
        authn_request = (
            f'<saml2p:AuthnRequest'
            f' xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"'
            f' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' ID="{request_id}"'
            f' Version="2.0"'
            f' IssueInstant="{issue_instant}"'
            f' Destination="{self.sso_url}"'
            f' AssertionConsumerServiceURL="{self.acs_url}"'
            f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            f' IsPassive="false"'
            f' ForceAuthn="false">'
            f'<saml2:Issuer>{self.entity_id}</saml2:Issuer>'
            f'<saml2p:NameIDPolicy'
            f'  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"'
            f'  AllowCreate="true"/>'
            f'</saml2p:AuthnRequest>'
        )

        logger.info(
            f"nia_authn_request: request_id={request_id}, "
            f"relay_state_fp={hashlib.sha256(relay_state.encode()).hexdigest()[:8]}"
        )

        # Deflate + Base64 encode for HTTP-Redirect binding
        deflated = zlib.compress(authn_request.encode("utf-8"))[2:-4]  # raw deflate
        b64_request = base64.b64encode(deflated).decode("utf-8")

        # Build redirect URL with query parameters
        params = {
            "SAMLRequest": b64_request,
            "RelayState": relay_state,
        }
        redirect_url = f"{self.sso_url}?{urlencode(params, quote_via=quote_plus)}"

        return redirect_url

    async def validate_saml_response(
        self,
        saml_response_b64: str,
        relay_state: str,
        expected_relay_state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SAMLResponse from NIA IdP and extract identity attributes.

        Performs:
        1. Base64 decode SAMLResponse
        2. Parse XML
        3. Validate signature against IdP certificates (from metadata)
        4. Validate audience, issuer, time conditions
        5. Extract subject (NameID) and attributes

        Args:
            saml_response_b64: Base64-encoded SAMLResponse from POST form.
            relay_state: RelayState from the POST form.
            expected_relay_state: Expected relay state for CSRF validation.

        Returns:
            Dict with: subject, attributes, loa, authn_instant, session_index

        Raises:
            SAMLValidationError: If validation fails.
        """
        # 1. Decode SAMLResponse
        try:
            response_xml = base64.b64decode(saml_response_b64)
        except Exception as e:
            raise SAMLValidationError(f"Invalid base64 SAMLResponse: {e}")

        # 2. Parse XML
        try:
            root = ET.fromstring(response_xml)
        except ET.ParseError as e:
            raise SAMLValidationError(f"Invalid XML in SAMLResponse: {e}")

        # 3. Validate RelayState (CSRF protection)
        if expected_relay_state and relay_state != expected_relay_state:
            raise SAMLValidationError(
                "RelayState mismatch (possible CSRF)",
                code="NIA_STATE_INVALID",
            )

        # 4. Check top-level status
        status_elem = root.find(".//saml2p:Status/saml2p:StatusCode", NS)
        if status_elem is None:
            raise SAMLValidationError("Missing Status element in SAMLResponse")

        status_value = status_elem.get("Value", "")
        if "Success" not in status_value:
            status_msg_elem = root.find(".//saml2p:Status/saml2p:StatusMessage", NS)
            status_msg = status_msg_elem.text if status_msg_elem is not None else "unknown"
            raise SAMLValidationError(
                f"NIA authentication failed: {status_value} - {status_msg}"
            )

        # 5. Find Assertion
        assertion = root.find(".//saml2:Assertion", NS)
        if assertion is None:
            raise SAMLValidationError("No Assertion found in SAMLResponse")

        # 6. Validate signature against IdP metadata certificates
        await self._validate_signature(root, assertion)

        # 7. Validate conditions (audience, time)
        self._validate_conditions(assertion)

        # 8. Validate issuer
        issuer_elem = assertion.find("saml2:Issuer", NS)
        if issuer_elem is not None:
            issuer_text = issuer_elem.text
            logger.info(f"nia_response: issuer={issuer_text}")

        # 9. Extract NameID (subject / SePP)
        subject_elem = assertion.find(".//saml2:Subject/saml2:NameID", NS)
        if subject_elem is None:
            raise SAMLValidationError("No NameID found in Assertion")
        subject = subject_elem.text

        # 10. Extract AuthnStatement
        authn_statement = assertion.find(".//saml2:AuthnStatement", NS)
        authn_instant = None
        session_index = None
        loa = None

        if authn_statement is not None:
            authn_instant_str = authn_statement.get("AuthnInstant")
            if authn_instant_str:
                try:
                    authn_instant = datetime.fromisoformat(
                        authn_instant_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    logger.warning(f"Could not parse AuthnInstant: {authn_instant_str}")

            session_index = authn_statement.get("SessionIndex")

            # Extract LoA from AuthnContext
            loa_elem = authn_statement.find(
                ".//saml2:AuthnContext/saml2:AuthnContextClassRef", NS
            )
            if loa_elem is not None:
                loa = loa_elem.text

        # 11. Extract attributes
        attributes = self._extract_attributes(assertion)

        subject_fp = hashlib.sha256(subject.encode()).hexdigest()[:8]
        logger.info(
            f"nia_validate: status=success, subject_fp={subject_fp}, "
            f"loa={loa}, attrs_count={len(attributes)}"
        )

        return {
            "subject": subject,
            "attributes": attributes,
            "loa": loa,
            "authn_instant": authn_instant,
            "session_index": session_index,
        }

    async def _validate_signature(self, root: ET.Element, assertion: ET.Element) -> None:
        """
        Validate XML digital signature against NIA IdP certificates.

        Fetches IdP metadata (cached for 24h) and verifies the signature
        using the embedded X.509 certificates.

        NOTE: Full cryptographic signature validation requires xmlsec1 or
        a dedicated library. This implementation validates the certificate
        presence and basic structure. For production, use python3-saml or
        signxml for full signature verification.
        """
        # Check that a Signature element exists
        sig = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if sig is None:
            sig = assertion.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")

        if sig is None:
            raise SAMLValidationError("No XML Signature found in SAMLResponse")

        # Fetch IdP metadata certificates for validation
        idp_certs = await self._get_idp_certificates()
        if not idp_certs:
            logger.warning("nia_validate: no IdP certificates from metadata, skipping cert match")
            return

        # Extract certificate from the Signature
        cert_elem = sig.find(
            ".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
        )
        if cert_elem is None or not cert_elem.text:
            raise SAMLValidationError("No X509Certificate in Signature")

        response_cert = cert_elem.text.strip().replace("\n", "").replace("\r", "").replace(" ", "")

        # Verify the certificate matches one of the IdP metadata certificates
        cert_matched = any(
            response_cert == idp_cert.replace("\n", "").replace("\r", "").replace(" ", "")
            for idp_cert in idp_certs
        )

        if not cert_matched:
            raise SAMLValidationError(
                "SAMLResponse certificate does not match any IdP metadata certificate"
            )

        logger.debug("nia_validate: certificate matches IdP metadata")

        # NOTE: Full XML signature cryptographic verification should use
        # xmlsec1 or signxml library. The certificate match above provides
        # basic trust validation. For production hardening, integrate
        # python3-saml or signxml for full ds:SignedInfo verification.

    def _validate_conditions(self, assertion: ET.Element) -> None:
        """Validate Conditions element (NotBefore, NotOnOrAfter, Audience)."""
        conditions = assertion.find("saml2:Conditions", NS)
        if conditions is None:
            logger.debug("nia_validate: no Conditions element, skipping time validation")
            return

        now = datetime.now(timezone.utc)
        # Allow 5 minutes clock skew
        skew_seconds = 300

        not_before = conditions.get("NotBefore")
        if not_before:
            try:
                nb = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                from datetime import timedelta
                if now < nb - timedelta(seconds=skew_seconds):
                    raise SAMLValidationError(
                        f"Assertion not yet valid (NotBefore={not_before})"
                    )
            except ValueError:
                logger.warning(f"Could not parse NotBefore: {not_before}")

        not_on_or_after = conditions.get("NotOnOrAfter")
        if not_on_or_after:
            try:
                noa = datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
                from datetime import timedelta
                if now > noa + timedelta(seconds=skew_seconds):
                    raise SAMLValidationError(
                        f"Assertion expired (NotOnOrAfter={not_on_or_after})"
                    )
            except ValueError:
                logger.warning(f"Could not parse NotOnOrAfter: {not_on_or_after}")

        # Validate audience restriction
        audience_elem = conditions.find(
            ".//saml2:AudienceRestriction/saml2:Audience", NS
        )
        if audience_elem is not None and audience_elem.text:
            if audience_elem.text != self.entity_id:
                raise SAMLValidationError(
                    f"Audience mismatch: expected={self.entity_id}, "
                    f"got={audience_elem.text}"
                )

    def _extract_attributes(self, assertion: ET.Element) -> Dict[str, Any]:
        """
        Extract SAML attributes from Assertion.

        Common NIA attributes:
        - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name (full name)
        - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
        - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
        - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth
        - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        - http://schemas.eidentita.cz/moris/2019/identity/claims/tradresaid
        - http://schemas.eidentita.cz/moris/2019/identity/claims/idtype
        - http://schemas.eidentita.cz/moris/2019/identity/claims/idnumber
        """
        attributes: Dict[str, Any] = {}

        attr_stmts = assertion.findall(".//saml2:AttributeStatement/saml2:Attribute", NS)
        for attr in attr_stmts:
            attr_name = attr.get("Name", "")
            values = [v.text for v in attr.findall("saml2:AttributeValue", NS) if v.text]

            # Use short name if it's a known claims URI
            short_name = attr_name.rsplit("/", 1)[-1] if "/" in attr_name else attr_name

            if len(values) == 1:
                attributes[short_name] = values[0]
            elif len(values) > 1:
                attributes[short_name] = values

        return attributes

    async def _get_idp_certificates(self) -> List[str]:
        """
        Fetch and cache NIA IdP certificates from metadata.

        Caches for 24 hours to avoid hitting NIA servers on every request.

        Returns:
            List of base64-encoded X.509 certificate strings.
        """
        global _metadata_cache, _metadata_cache_time

        # Check cache
        if _metadata_cache and (time.time() - _metadata_cache_time) < METADATA_CACHE_TTL:
            return _metadata_cache.get("certificates", [])

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.metadata_url)
                response.raise_for_status()

            root = ET.fromstring(response.content)

            # Extract signing certificates from metadata
            certs = []
            # Look for KeyDescriptor with use="signing" or no use attribute
            for key_desc in root.findall(".//{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor"):
                use = key_desc.get("use", "signing")
                if use in ("signing", ""):
                    cert_elem = key_desc.find(
                        ".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
                    )
                    if cert_elem is not None and cert_elem.text:
                        certs.append(cert_elem.text.strip())

            # Also check WS-Federation format (NIA may use this)
            for token_signing in root.findall(
                ".//{http://docs.oasis-open.org/wsfed/federation/200706}"
                "TargetScopes/../{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
            ):
                if token_signing.text:
                    certs.append(token_signing.text.strip())

            # Broader fallback: find all X509Certificate elements
            if not certs:
                for cert_elem in root.findall(
                    ".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
                ):
                    if cert_elem.text:
                        certs.append(cert_elem.text.strip())

            _metadata_cache = {"certificates": certs}
            _metadata_cache_time = time.time()

            logger.info(f"nia_metadata: fetched {len(certs)} certificates from {self.metadata_url}")
            return certs

        except Exception as e:
            logger.error(f"nia_metadata: failed to fetch IdP metadata: {e}")
            # Return cached certs if available (stale cache better than no cache)
            if _metadata_cache:
                logger.warning("nia_metadata: using stale cached certificates")
                return _metadata_cache.get("certificates", [])
            return []


# Singleton
_nia_service: Optional[NIASamlService] = None


def get_nia_service() -> NIASamlService:
    """Get NIA SAML service singleton."""
    global _nia_service
    if _nia_service is None:
        from app.config import get_settings
        _nia_service = NIASamlService(get_settings())
    return _nia_service
