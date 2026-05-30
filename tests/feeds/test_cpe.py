"""Tests for loki.feeds.cpe — CPE-2.3 parser and formatter."""

from __future__ import annotations

import pytest

from loki.feeds.cpe import CPETriple, format_cpe, parse_cpe


class TestParseCpe:
    """Tests for parse_cpe()."""

    def test_valid_os_cpe(self) -> None:
        result = parse_cpe("cpe:2.3:o:intel:firmware:1.2.3:*:*:*:*:*:*:*")
        assert result == CPETriple(vendor="intel", product="firmware", version="1.2.3")

    def test_valid_application_cpe(self) -> None:
        result = parse_cpe("cpe:2.3:a:microsoft:edge:120.0.2210.91:*:*:*:*:*:*:*")
        assert result == CPETriple(vendor="microsoft", product="edge", version="120.0.2210.91")

    def test_valid_hardware_cpe(self) -> None:
        result = parse_cpe("cpe:2.3:h:cisco:asr_9000:-:*:*:*:*:*:*:*")
        assert result == CPETriple(vendor="cisco", product="asr_9000", version="-")

    def test_valid_nvd_example_linux(self) -> None:
        cpe = "cpe:2.3:o:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*"
        result = parse_cpe(cpe)
        assert result.vendor == "linux"
        assert result.product == "linux_kernel"
        assert result.version == "5.15.0"

    def test_valid_nvd_example_apache(self) -> None:
        cpe = "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"
        result = parse_cpe(cpe)
        assert result.vendor == "apache"
        assert result.product == "http_server"
        assert result.version == "2.4.51"

    def test_wildcard_version(self) -> None:
        result = parse_cpe("cpe:2.3:o:intel:firmware:*:*:*:*:*:*:*:*")
        assert result.version == "*"

    def test_na_version(self) -> None:
        result = parse_cpe("cpe:2.3:h:dell:bios:-:*:*:*:*:*:*:*")
        assert result.version == "-"

    def test_wildcard_part(self) -> None:
        result = parse_cpe("cpe:2.3:*:somevendor:someproduct:1.0:*:*:*:*:*:*:*")
        assert result.vendor == "somevendor"

    def test_na_part(self) -> None:
        result = parse_cpe("cpe:2.3:-:somevendor:someproduct:1.0:*:*:*:*:*:*:*")
        assert result.vendor == "somevendor"

    def test_escaped_colon_in_vendor(self) -> None:
        # A vendor with an escaped colon: "foo\:bar"
        cpe = "cpe:2.3:o:foo\\:bar:product:1.0:*:*:*:*:*:*:*"
        result = parse_cpe(cpe)
        assert result.vendor == "foo\\:bar"

    def test_escaped_colon_in_product(self) -> None:
        cpe = "cpe:2.3:o:vendor:prod\\:uct:2.0:*:*:*:*:*:*:*"
        result = parse_cpe(cpe)
        assert result.product == "prod\\:uct"


class TestParseCpeErrors:
    """Tests for parse_cpe() error cases."""

    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Empty CPE string"):
            parse_cpe("")

    def test_wrong_prefix(self) -> None:
        with pytest.raises(ValueError, match="invalid prefix"):
            parse_cpe("cpe:2.2:o:intel:firmware:1.0:*:*:*:*:*:*:*")

    def test_too_few_fields(self) -> None:
        with pytest.raises(ValueError, match="fields"):
            parse_cpe("cpe:2.3:o:intel:firmware")

    def test_missing_cpe_prefix(self) -> None:
        with pytest.raises(ValueError, match="invalid prefix"):
            parse_cpe("xxx:2.3:o:intel:firmware:1.0:*:*:*:*:*:*:*")

    def test_invalid_part_value(self) -> None:
        with pytest.raises(ValueError, match="unrecognized part"):
            parse_cpe("cpe:2.3:z:intel:firmware:1.0:*:*:*:*:*:*:*")


class TestFormatCpe:
    """Tests for format_cpe()."""

    def test_basic_format(self) -> None:
        triple = CPETriple(vendor="intel", product="firmware", version="1.2.3")
        result = format_cpe(triple)
        assert result == "cpe:2.3:o:intel:firmware:1.2.3:*:*:*:*:*:*:*"

    def test_format_with_part(self) -> None:
        triple = CPETriple(vendor="microsoft", product="edge", version="120.0")
        result = format_cpe(triple, part="a")
        assert result == "cpe:2.3:a:microsoft:edge:120.0:*:*:*:*:*:*:*"

    def test_format_wildcard_version(self) -> None:
        triple = CPETriple(vendor="linux", product="kernel", version="*")
        result = format_cpe(triple)
        assert result == "cpe:2.3:o:linux:kernel:*:*:*:*:*:*:*:*"

    def test_format_na_version(self) -> None:
        triple = CPETriple(vendor="dell", product="bios", version="-")
        result = format_cpe(triple)
        assert result == "cpe:2.3:o:dell:bios:-:*:*:*:*:*:*:*"

    def test_format_produces_13_fields(self) -> None:
        triple = CPETriple(vendor="v", product="p", version="1")
        result = format_cpe(triple)
        # Split carefully respecting escaped colons — but in this case there are none.
        assert result.count(":") == 12  # 13 fields = 12 colons


class TestRoundTrip:
    """Round-trip: parse -> format -> parse."""

    @pytest.mark.parametrize(
        "cpe_string",
        [
            "cpe:2.3:o:intel:firmware:1.2.3:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
            "cpe:2.3:h:cisco:asr_9000:-:*:*:*:*:*:*:*",
            "cpe:2.3:o:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*",
        ],
    )
    def test_roundtrip(self, cpe_string: str) -> None:
        parsed = parse_cpe(cpe_string)
        # Determine part from original.
        part = cpe_string.split(":")[2]
        formatted = format_cpe(parsed, part=part)
        reparsed = parse_cpe(formatted)
        assert reparsed == parsed

    def test_roundtrip_with_escaped_colon(self) -> None:
        cpe = "cpe:2.3:o:foo\\:bar:product:1.0:*:*:*:*:*:*:*"
        parsed = parse_cpe(cpe)
        formatted = format_cpe(parsed, part="o")
        reparsed = parse_cpe(formatted)
        assert reparsed == parsed


class TestSpecialValues:
    """Wildcard and NA pass-through."""

    def test_wildcard_passthrough(self) -> None:
        triple = CPETriple(vendor="*", product="*", version="*")
        formatted = format_cpe(triple)
        reparsed = parse_cpe(formatted)
        assert reparsed == triple

    def test_na_passthrough(self) -> None:
        triple = CPETriple(vendor="-", product="-", version="-")
        formatted = format_cpe(triple)
        reparsed = parse_cpe(formatted)
        assert reparsed == triple
