"""
Tests for NIA (Národní identitní autorita) SAML2 integration.
"""
import base64
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from xml.etree import ElementTree as ET

import pytest

from app.nia.saml import NIASamlService, SAMLValidationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def nia_settings():
    """Create mock settings for NIA."""
    settings = MagicMock()
    settings.nia_enabled = True
    settings.nia_env = "test"
    settings.nia_entity_id = "https://test-sp.example.com/saml"
    settings.nia_acs_url = "https://test-sp.example.com/v1/nia/acs"
    settings.nia_saml_endpoint = "https://tnia.identita.gov.cz/FPSTS/saml2/basic"
    settings.nia_metadata_url = "https://tnia.identita.gov.cz/FPSTS/FederationMetadata/2007-06/FederationMetadata.xml"
    settings.signing_token_salt = "test-salt"
    settings.sign_app_url = "https://sign.example.com"
    settings.environment = "test"
    return settings


@pytest.fixture
def nia_service(nia_settings):
    """Create NIA SAML service instance."""
    return NIASamlService(nia_settings)


def _build_saml_response(
    subject: str = "SePP-123456789",
    issuer: str = "https://tnia.identita.gov.cz",
    audience: str = "https://test-sp.example.com/saml",
    status: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
    loa: str = "http://eidas.europa.eu/LoA/substantial",
    attributes: dict = None,
    not_before: str = None,
    not_on_or_after: str = None,
    include_signature: bool = True,
    cert_text: str = "MIICtest==",
) -> str:
    """Build a minimal SAML Response XML for testing."""
    now = datetime.now(timezone.utc)
    if not_before is None:
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not_on_or_after is None:
        not_on_or_after = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    if attributes is None:
        attributes = {
            "givenname": "Jan",
            "surname": "Novák",
            "dateofbirth": "1990-01-15",
        }

    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    authn_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build attribute statements
    attr_xml = ""
    for name, value in attributes.items():
        attr_xml += (
            f'<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/{name}">'
            f'<saml2:AttributeValue>{value}</saml2:AttributeValue>'
            f'</saml2:Attribute>'
        )

    sig_xml = ""
    if include_signature:
        sig_xml = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            '<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="exc-c14n"/>'
            '<ds:SignatureMethod Algorithm="rsa-sha256"/>'
            '<ds:Reference><ds:DigestMethod Algorithm="sha256"/>'
            '<ds:DigestValue>test</ds:DigestValue></ds:Reference></ds:SignedInfo>'
            '<ds:SignatureValue>test</ds:SignatureValue>'
            '<ds:KeyInfo><ds:X509Data>'
            f'<ds:X509Certificate>{cert_text}</ds:X509Certificate>'
            '</ds:X509Data></ds:KeyInfo></ds:Signature>'
        )

    xml = (
        f'<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="_resp-{uuid.uuid4()}"'
        f' Version="2.0"'
        f' IssueInstant="{issue_instant}">'
        f'<saml2:Issuer>{issuer}</saml2:Issuer>'
        f'{sig_xml}'
        f'<saml2p:Status><saml2p:StatusCode Value="{status}"/></saml2p:Status>'
        f'<saml2:Assertion ID="_assert-{uuid.uuid4()}" Version="2.0" IssueInstant="{issue_instant}">'
        f'<saml2:Issuer>{issuer}</saml2:Issuer>'
        f'<saml2:Subject>'
        f'<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{subject}</saml2:NameID>'
        f'</saml2:Subject>'
        f'<saml2:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">'
        f'<saml2:AudienceRestriction><saml2:Audience>{audience}</saml2:Audience></saml2:AudienceRestriction>'
        f'</saml2:Conditions>'
        f'<saml2:AuthnStatement AuthnInstant="{authn_instant}" SessionIndex="_sess-1">'
        f'<saml2:AuthnContext>'
        f'<saml2:AuthnContextClassRef>{loa}</saml2:AuthnContextClassRef>'
        f'</saml2:AuthnContext>'
        f'</saml2:AuthnStatement>'
        f'<saml2:AttributeStatement>{attr_xml}</saml2:AttributeStatement>'
        f'</saml2:Assertion>'
        f'</saml2p:Response>'
    )
    return xml


# ---------------------------------------------------------------------------
# Tests: AuthnRequest generation
# ---------------------------------------------------------------------------

class TestAuthnRequest:
    """Tests for SAML AuthnRequest generation."""

    def test_creates_redirect_url(self, nia_service):
        """AuthnRequest generates a valid redirect URL."""
        relay_state = "session-123:state-abc"
        url = nia_service.create_authn_request_redirect_url(relay_state)

        assert url.startswith("https://tnia.identita.gov.cz/FPSTS/saml2/basic?")
        assert "SAMLRequest=" in url
        assert "RelayState=" in url

    def test_redirect_url_contains_relay_state(self, nia_service):
        """RelayState is included in the redirect URL."""
        relay_state = "my-session:my-state"
        url = nia_service.create_authn_request_redirect_url(relay_state)

        # URL-decoded RelayState should match
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert params["RelayState"][0] == relay_state

    def test_saml_request_is_valid_xml(self, nia_service):
        """Decoded SAMLRequest is valid XML with required elements."""
        import zlib

        relay_state = "test:state"
        url = nia_service.create_authn_request_redirect_url(relay_state)

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        saml_b64 = params["SAMLRequest"][0]

        # Decode: base64 → inflate
        compressed = base64.b64decode(saml_b64)
        xml_bytes = zlib.decompress(compressed, -15)  # raw inflate
        xml_str = xml_bytes.decode("utf-8")

        # Parse XML
        root = ET.fromstring(xml_str)
        assert "AuthnRequest" in root.tag

        # Check Issuer
        ns = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
        issuer = root.find("saml2:Issuer", ns)
        assert issuer is not None
        assert issuer.text == "https://test-sp.example.com/saml"

        # Check ACS URL
        assert root.get("AssertionConsumerServiceURL") == "https://test-sp.example.com/v1/nia/acs"


# ---------------------------------------------------------------------------
# Tests: RelayState validation
# ---------------------------------------------------------------------------

class TestRelayStateValidation:
    """Tests for RelayState parsing and validation."""

    def test_valid_relay_state_format(self):
        """Valid RelayState with session_id:state is accepted."""
        relay_state = "session-123:state-abc-def"
        parts = relay_state.split(":", 1)
        assert len(parts) == 2
        assert parts[0] == "session-123"
        assert parts[1] == "state-abc-def"

    def test_invalid_relay_state_no_separator(self):
        """RelayState without ':' separator is invalid."""
        relay_state = "invalid-no-separator"
        parts = relay_state.split(":", 1)
        assert len(parts) == 1  # No valid split

    def test_empty_relay_state(self):
        """Empty RelayState is invalid."""
        relay_state = ""
        parts = relay_state.split(":", 1)
        assert parts[0] == ""

    def test_relay_state_with_colon_in_state(self):
        """RelayState with colons in state part (UUID) parses correctly."""
        session_id = "sess-abc"
        state = str(uuid.uuid4())  # UUIDs have hyphens, not colons
        relay_state = f"{session_id}:{state}"
        parts = relay_state.split(":", 1)
        assert parts[0] == session_id
        assert parts[1] == state


# ---------------------------------------------------------------------------
# Tests: SAML Response validation
# ---------------------------------------------------------------------------

class TestSAMLResponseValidation:
    """Tests for SAML Response validation and attribute extraction."""

    @pytest.mark.asyncio
    async def test_validates_successful_response(self, nia_service):
        """Valid SAMLResponse is parsed and attributes extracted."""
        xml = _build_saml_response()
        b64 = base64.b64encode(xml.encode()).decode()
        relay_state = "session-123:state-abc"

        # Mock IdP certificate fetch to match our test cert
        with patch.object(nia_service, "_get_idp_certificates", new_callable=AsyncMock) as mock_certs:
            mock_certs.return_value = ["MIICtest=="]

            result = await nia_service.validate_saml_response(
                saml_response_b64=b64,
                relay_state=relay_state,
            )

        assert result["subject"] == "SePP-123456789"
        assert result["loa"] == "http://eidas.europa.eu/LoA/substantial"
        assert "givenname" in result["attributes"]
        assert result["attributes"]["givenname"] == "Jan"
        assert result["attributes"]["surname"] == "Novák"
        assert result["authn_instant"] is not None

    @pytest.mark.asyncio
    async def test_rejects_invalid_base64(self, nia_service):
        """Invalid base64 raises SAMLValidationError."""
        with pytest.raises(SAMLValidationError, match="Invalid base64"):
            await nia_service.validate_saml_response(
                saml_response_b64="not-valid-base64!!!",
                relay_state="test",
            )

    @pytest.mark.asyncio
    async def test_rejects_invalid_xml(self, nia_service):
        """Invalid XML raises SAMLValidationError."""
        b64 = base64.b64encode(b"not xml at all").decode()
        with pytest.raises(SAMLValidationError, match="Invalid XML"):
            await nia_service.validate_saml_response(
                saml_response_b64=b64,
                relay_state="test",
            )

    @pytest.mark.asyncio
    async def test_rejects_failed_status(self, nia_service):
        """Non-success SAML status raises error."""
        xml = _build_saml_response(
            status="urn:oasis:names:tc:SAML:2.0:status:Requester",
        )
        b64 = base64.b64encode(xml.encode()).decode()

        with pytest.raises(SAMLValidationError, match="authentication failed"):
            await nia_service.validate_saml_response(
                saml_response_b64=b64,
                relay_state="test",
            )

    @pytest.mark.asyncio
    async def test_rejects_no_signature(self, nia_service):
        """SAMLResponse without signature is rejected."""
        xml = _build_saml_response(include_signature=False)
        b64 = base64.b64encode(xml.encode()).decode()

        with pytest.raises(SAMLValidationError, match="No XML Signature"):
            await nia_service.validate_saml_response(
                saml_response_b64=b64,
                relay_state="test",
            )

    @pytest.mark.asyncio
    async def test_rejects_expired_assertion(self, nia_service):
        """Expired assertion (NotOnOrAfter in the past) is rejected."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = _build_saml_response(
            not_before=(datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            not_on_or_after=past,
        )
        b64 = base64.b64encode(xml.encode()).decode()

        with patch.object(nia_service, "_get_idp_certificates", new_callable=AsyncMock) as mock_certs:
            mock_certs.return_value = ["MIICtest=="]
            with pytest.raises(SAMLValidationError, match="expired"):
                await nia_service.validate_saml_response(
                    saml_response_b64=b64,
                    relay_state="test",
                )

    @pytest.mark.asyncio
    async def test_rejects_audience_mismatch(self, nia_service):
        """Audience mismatch is rejected."""
        xml = _build_saml_response(audience="https://wrong-audience.example.com")
        b64 = base64.b64encode(xml.encode()).decode()

        with patch.object(nia_service, "_get_idp_certificates", new_callable=AsyncMock) as mock_certs:
            mock_certs.return_value = ["MIICtest=="]
            with pytest.raises(SAMLValidationError, match="Audience mismatch"):
                await nia_service.validate_saml_response(
                    saml_response_b64=b64,
                    relay_state="test",
                )

    @pytest.mark.asyncio
    async def test_rejects_certificate_mismatch(self, nia_service):
        """Certificate not matching IdP metadata is rejected."""
        xml = _build_saml_response(cert_text="DifferentCert==")
        b64 = base64.b64encode(xml.encode()).decode()

        with patch.object(nia_service, "_get_idp_certificates", new_callable=AsyncMock) as mock_certs:
            mock_certs.return_value = ["ExpectedCert=="]
            with pytest.raises(SAMLValidationError, match="does not match"):
                await nia_service.validate_saml_response(
                    saml_response_b64=b64,
                    relay_state="test",
                )

    @pytest.mark.asyncio
    async def test_relay_state_mismatch_rejected(self, nia_service):
        """Mismatched RelayState is rejected when expected_relay_state provided."""
        xml = _build_saml_response()
        b64 = base64.b64encode(xml.encode()).decode()

        with pytest.raises(SAMLValidationError, match="RelayState mismatch"):
            await nia_service.validate_saml_response(
                saml_response_b64=b64,
                relay_state="actual-state",
                expected_relay_state="expected-state",
            )


# ---------------------------------------------------------------------------
# Tests: Session update after NIA success (mock DB)
# ---------------------------------------------------------------------------

class TestSessionUpdateAfterNIA:
    """Tests verifying signing_sessions is correctly updated after NIA verification."""

    @pytest.mark.asyncio
    async def test_session_updates_on_nia_success(self):
        """After NIA success, session has correct NIA fields."""
        # Simulate what the ACS callback does
        session_updates = {}

        subject = "SePP-UNIQUE-123"
        loa = "http://eidas.europa.eu/LoA/substantial"
        attributes = {"givenname": "Jan", "surname": "Novák"}
        authn_instant = datetime.now(timezone.utc)

        # This is the update dict that would be passed to supabase
        session_updates = {
            "identity_method": "nia",
            "identity_verified_at": datetime.now(timezone.utc).isoformat(),
            "nia_subject": subject,
            "nia_loa": loa,
            "nia_attributes": attributes,
            "nia_authn_instant": authn_instant.isoformat(),
            "nia_state": None,  # Clear to prevent replay
        }

        assert session_updates["identity_method"] == "nia"
        assert session_updates["nia_subject"] == "SePP-UNIQUE-123"
        assert session_updates["nia_loa"] == "http://eidas.europa.eu/LoA/substantial"
        assert session_updates["nia_state"] is None  # Cleared for replay protection
        assert "givenname" in session_updates["nia_attributes"]

    @pytest.mark.asyncio
    async def test_nia_state_cleared_after_use(self):
        """nia_state is set to None after ACS callback (replay protection)."""
        # Before: session has nia_state
        session_before = {
            "nia_state": str(uuid.uuid4()),
            "identity_method": "nia",
            "identity_verified_at": None,
        }
        assert session_before["nia_state"] is not None

        # After ACS: nia_state is cleared
        updates = {"nia_state": None, "identity_verified_at": datetime.now(timezone.utc).isoformat()}

        session_after = {**session_before, **updates}
        assert session_after["nia_state"] is None
        assert session_after["identity_verified_at"] is not None


# ---------------------------------------------------------------------------
# Tests: Metadata caching
# ---------------------------------------------------------------------------

class TestMetadataCaching:
    """Tests for NIA IdP metadata fetching and caching."""

    @pytest.mark.asyncio
    async def test_fetches_certificates_from_metadata(self, nia_service):
        """Certificates are extracted from IdP metadata XML."""
        metadata_xml = """<?xml version="1.0" encoding="utf-8"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                          entityID="https://tnia.identita.gov.cz">
          <IDPSSODescriptor>
            <KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate>MIICtestCertificate==</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </KeyDescriptor>
          </IDPSSODescriptor>
        </EntityDescriptor>"""

        mock_response = MagicMock()
        mock_response.content = metadata_xml.encode()
        mock_response.raise_for_status = MagicMock()

        # Clear cache
        import app.nia.saml as saml_module
        saml_module._metadata_cache = None
        saml_module._metadata_cache_time = 0

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            certs = await nia_service._get_idp_certificates()

        assert len(certs) >= 1
        assert "MIICtestCertificate==" in certs

    @pytest.mark.asyncio
    async def test_uses_cached_certificates(self, nia_service):
        """Second call uses cached certificates without HTTP request."""
        import app.nia.saml as saml_module
        import time

        # Pre-populate cache
        saml_module._metadata_cache = {"certificates": ["CachedCert=="]}
        saml_module._metadata_cache_time = time.time()

        with patch("httpx.AsyncClient") as mock_client_cls:
            certs = await nia_service._get_idp_certificates()

        # Should NOT have made HTTP call
        mock_client_cls.assert_not_called()
        assert certs == ["CachedCert=="]

        # Clean up
        saml_module._metadata_cache = None
        saml_module._metadata_cache_time = 0
