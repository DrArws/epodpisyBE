"""
Tests for verification field mapping in signer creation.
"""
import pytest
from app.models import SignerInput, VerificationMethod, SignerResponse


class TestVerificationMethod:
    """Tests for VerificationMethod enum."""

    def test_verification_method_values(self):
        """Test that all expected verification methods exist."""
        assert VerificationMethod.NONE.value == "none"
        assert VerificationMethod.SMS.value == "sms"
        assert VerificationMethod.EMAIL.value == "email"

    def test_verification_method_from_string(self):
        """Test parsing verification method from string."""
        assert VerificationMethod("none") == VerificationMethod.NONE
        assert VerificationMethod("sms") == VerificationMethod.SMS
        assert VerificationMethod("email") == VerificationMethod.EMAIL


class TestSignerInputVerification:
    """Tests for SignerInput model with verification field."""

    def test_signer_input_parses_verification_none(self):
        """Test that SignerInput correctly parses verification='none'."""
        signer = SignerInput(
            name="Test Signer",
            email="test@example.com",
            verification="none",
        )
        assert signer.verification == VerificationMethod.NONE
        assert signer.verification.value == "none"

    def test_signer_input_parses_verification_sms(self):
        """Test that SignerInput correctly parses verification='sms'."""
        signer = SignerInput(
            name="Test Signer",
            email="test@example.com",
            phone="+420123456789",
            verification="sms",
        )
        assert signer.verification == VerificationMethod.SMS
        assert signer.verification.value == "sms"

    def test_signer_input_verification_default_none(self):
        """Test that verification defaults to None when not provided."""
        signer = SignerInput(
            name="Test Signer",
            email="test@example.com",
        )
        assert signer.verification is None

    def test_signer_input_invalid_verification_raises(self):
        """Test that invalid verification value raises error."""
        with pytest.raises(ValueError):
            SignerInput(
                name="Test Signer",
                verification="invalid_value",
            )


class TestSignerDataMapping:
    """Tests for mapping verification to DB payload."""

    def test_create_signer_maps_verification_to_db_payload(self):
        """Test that verification is correctly mapped to DB insert payload."""
        signer_input = SignerInput(
            name="Test Signer",
            email="test@example.com",
            phone="+420123456789",
            verification="none",
        )

        # Simulate the mapping logic from create_document endpoint
        verification_provided = signer_input.verification is not None
        verification_value = signer_input.verification.value if verification_provided else None

        signer_data = {
            "name": signer_input.name,
            "email": signer_input.email,
            "phone": signer_input.phone,
            "signing_order": signer_input.signing_order,
        }

        if verification_provided:
            signer_data["verification"] = verification_value

        # Assertions
        assert verification_provided is True
        assert verification_value == "none"
        assert signer_data["verification"] == "none"

    def test_create_signer_preserves_db_default_when_not_provided(self):
        """Test that verification is NOT set when not provided (preserves DB default)."""
        signer_input = SignerInput(
            name="Test Signer",
            email="test@example.com",
        )

        # Simulate the mapping logic from create_document endpoint
        verification_provided = signer_input.verification is not None
        verification_value = signer_input.verification.value if verification_provided else None

        signer_data = {
            "name": signer_input.name,
            "email": signer_input.email,
            "signing_order": signer_input.signing_order,
        }

        if verification_provided:
            signer_data["verification"] = verification_value

        # Assertions - verification should NOT be in payload
        assert verification_provided is False
        assert verification_value is None
        assert "verification" not in signer_data


class TestSignerResponse:
    """Tests for SignerResponse model with verification field."""

    def test_signer_response_includes_verification(self):
        """Test that SignerResponse correctly includes verification field."""
        response = SignerResponse(
            id="test-id",
            name="Test Signer",
            email="test@example.com",
            status="pending",
            signing_order=1,
            verification="none",
        )
        assert response.verification == "none"

    def test_signer_response_verification_optional(self):
        """Test that verification is optional in SignerResponse."""
        response = SignerResponse(
            id="test-id",
            name="Test Signer",
            status="pending",
            signing_order=1,
        )
        assert response.verification is None
