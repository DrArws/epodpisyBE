"""
Tests for PDF signature placement validation.
"""
import pytest
from app.pdf.sign import (
    SignaturePlacement,
    PlacementValidationError,
    validate_placement,
    PLACEMENT_BOUNDS_TOLERANCE,
)


# Standard A4 page dimensions in points (72 points per inch)
A4_WIDTH = 595.0   # 210mm
A4_HEIGHT = 842.0  # 297mm


class TestPlacementValidation:
    """Test validate_placement() function."""

    def test_valid_placement_accepted(self):
        """Valid placement within page bounds is accepted."""
        placement = SignaturePlacement(page=1, x=100, y=100, w=180, h=50)
        # Should not raise
        validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)

    def test_valid_placement_last_page(self):
        """Valid placement on last page is accepted."""
        placement = SignaturePlacement(page=5, x=100, y=100, w=180, h=50)
        validate_placement(placement, page_count=5, page_width=A4_WIDTH, page_height=A4_HEIGHT)

    def test_valid_placement_edge_of_page(self):
        """Placement at edge of page (within tolerance) is accepted."""
        # Signature exactly at right edge
        placement = SignaturePlacement(
            page=1,
            x=A4_WIDTH - 180,  # Will end exactly at page width
            y=100,
            w=180,
            h=50
        )
        validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)

    def test_valid_placement_with_tolerance(self):
        """Placement slightly over edge (within tolerance) is accepted."""
        # Signature slightly over right edge but within tolerance
        placement = SignaturePlacement(
            page=1,
            x=A4_WIDTH - 180 + PLACEMENT_BOUNDS_TOLERANCE - 0.5,
            y=100,
            w=180,
            h=50
        )
        validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)


class TestPageValidation:
    """Test page number validation."""

    def test_page_zero_rejected(self):
        """Page 0 is rejected (1-indexed)."""
        placement = SignaturePlacement(page=0, x=100, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=5, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_PAGE_NUMBER"

    def test_negative_page_rejected(self):
        """Negative page number is rejected."""
        placement = SignaturePlacement(page=-1, x=100, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=5, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_PAGE_NUMBER"

    def test_page_exceeds_count_rejected(self):
        """Page number exceeding document page count is rejected."""
        placement = SignaturePlacement(page=6, x=100, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=5, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "PAGE_OUT_OF_RANGE"
        assert "5" in exc_info.value.message  # Should mention page count

    def test_page_100_on_3page_doc_rejected(self):
        """Page 100 on 3-page document is rejected."""
        placement = SignaturePlacement(page=100, x=100, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=3, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "PAGE_OUT_OF_RANGE"


class TestDimensionValidation:
    """Test width/height validation."""

    def test_zero_width_rejected(self):
        """Zero width is rejected."""
        placement = SignaturePlacement(page=1, x=100, y=100, w=0, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_WIDTH"

    def test_negative_width_rejected(self):
        """Negative width is rejected."""
        placement = SignaturePlacement(page=1, x=100, y=100, w=-50, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_WIDTH"

    def test_zero_height_rejected(self):
        """Zero height is rejected."""
        placement = SignaturePlacement(page=1, x=100, y=100, w=180, h=0)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_HEIGHT"

    def test_negative_height_rejected(self):
        """Negative height is rejected."""
        placement = SignaturePlacement(page=1, x=100, y=100, w=180, h=-20)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_HEIGHT"


class TestPositionValidation:
    """Test x/y position validation."""

    def test_negative_x_rejected(self):
        """Negative X position is rejected."""
        placement = SignaturePlacement(page=1, x=-10, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_X_POSITION"

    def test_negative_y_rejected(self):
        """Negative Y position is rejected."""
        placement = SignaturePlacement(page=1, x=100, y=-20, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "INVALID_Y_POSITION"

    def test_zero_position_accepted(self):
        """Zero X and Y positions are valid (top-left corner)."""
        placement = SignaturePlacement(page=1, x=0, y=0, w=180, h=50)
        # Should not raise
        validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)


class TestBoundsValidation:
    """Test bounds checking (signature within page)."""

    def test_exceeds_right_edge_rejected(self):
        """Signature extending beyond right edge is rejected."""
        placement = SignaturePlacement(
            page=1,
            x=500,  # 500 + 180 = 680 > 595 (A4 width)
            y=100,
            w=180,
            h=50
        )
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "EXCEEDS_PAGE_WIDTH"

    def test_exceeds_top_edge_rejected(self):
        """Signature extending beyond top edge is rejected."""
        placement = SignaturePlacement(
            page=1,
            x=100,
            y=800,  # 800 + 50 = 850 > 842 (A4 height)
            w=180,
            h=50
        )
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "EXCEEDS_PAGE_HEIGHT"

    def test_signature_larger_than_page_rejected(self):
        """Signature larger than page is rejected."""
        placement = SignaturePlacement(
            page=1,
            x=0,
            y=0,
            w=1000,  # Larger than A4 width
            h=1000   # Larger than A4 height
        )
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        # Should fail on width first
        assert exc_info.value.code == "EXCEEDS_PAGE_WIDTH"

    def test_barely_exceeds_tolerance_rejected(self):
        """Placement slightly over tolerance is rejected."""
        placement = SignaturePlacement(
            page=1,
            x=A4_WIDTH - 180 + PLACEMENT_BOUNDS_TOLERANCE + 1,  # Just over tolerance
            y=100,
            w=180,
            h=50
        )
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert exc_info.value.code == "EXCEEDS_PAGE_WIDTH"


class TestErrorMessages:
    """Test that error messages are informative."""

    def test_page_error_includes_page_count(self):
        """Page out of range error includes document page count."""
        placement = SignaturePlacement(page=10, x=100, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=3, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        assert "3" in exc_info.value.message
        assert "10" in exc_info.value.message

    def test_bounds_error_includes_dimensions(self):
        """Bounds error includes actual dimensions."""
        placement = SignaturePlacement(page=1, x=500, y=100, w=180, h=50)
        with pytest.raises(PlacementValidationError) as exc_info:
            validate_placement(placement, page_count=1, page_width=A4_WIDTH, page_height=A4_HEIGHT)
        # Should include computed value and page width
        assert "680" in exc_info.value.message  # 500 + 180
        assert str(int(A4_WIDTH)) in exc_info.value.message


class TestPlacementValidationErrorClass:
    """Test PlacementValidationError class."""

    def test_error_has_code_and_message(self):
        """Error has both code and message attributes."""
        error = PlacementValidationError("Test message", "TEST_CODE")
        assert error.code == "TEST_CODE"
        assert error.message == "Test message"
        assert str(error) == "Test message"

    def test_default_code(self):
        """Default error code is INVALID_PLACEMENT."""
        error = PlacementValidationError("Test message")
        assert error.code == "INVALID_PLACEMENT"
