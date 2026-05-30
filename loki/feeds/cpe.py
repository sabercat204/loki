"""Hand-rolled minimal CPE-2.3 parser and formatter."""

from __future__ import annotations

from dataclasses import dataclass

__all__: list[str] = [
    "CPETriple",
    "format_cpe",
    "parse_cpe",
]


@dataclass(frozen=True)
class CPETriple:
    """Vendor, product, version triple extracted from a CPE-2.3 formatted string."""

    vendor: str
    product: str
    version: str


def _split_cpe_fields(cpe_string: str) -> list[str]:
    """Split a CPE-2.3 string on unescaped colons.

    Escaped colons (``\\:``) are preserved within field values.
    """
    fields: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(cpe_string):
        if cpe_string[i] == "\\" and i + 1 < len(cpe_string) and cpe_string[i + 1] == ":":
            current.append("\\:")
            i += 2
        elif cpe_string[i] == ":":
            fields.append("".join(current))
            current = []
            i += 1
        else:
            current.append(cpe_string[i])
            i += 1
    fields.append("".join(current))
    return fields


def parse_cpe(cpe_string: str) -> CPETriple:
    """Parse a CPE-2.3 formatted-string into its (vendor, product, version) triple.

    Handles the wfn-fs-string form: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    Raises ValueError on malformed input.
    """
    if not cpe_string:
        raise ValueError("Empty CPE string")

    fields = _split_cpe_fields(cpe_string)

    # Must have at least 13 colon-separated fields.
    if len(fields) < 13:
        raise ValueError(
            f"CPE string has {len(fields)} fields, expected at least 13: {cpe_string!r}"
        )

    # Validate prefix.
    if fields[0] != "cpe" or fields[1] != "2.3":
        raise ValueError(f"CPE string has invalid prefix: {cpe_string!r}")

    # Validate part field (fields[2]) is a recognized part.
    part = fields[2]
    if part not in ("a", "h", "o", "*", "-"):
        raise ValueError(f"CPE string has unrecognized part value {part!r}: {cpe_string!r}")

    vendor = fields[3]
    product = fields[4]
    version = fields[5]

    return CPETriple(vendor=vendor, product=product, version=version)


def _escape_unescaped_colons(value: str) -> str:
    """Escape only bare (unescaped) colons in a CPE field value.

    Already-escaped sequences (``\\:``) are left intact.
    """
    result: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value) and value[i + 1] == ":":
            # Already escaped — pass through.
            result.append("\\:")
            i += 2
        elif value[i] == ":":
            # Bare colon — escape it.
            result.append("\\:")
            i += 1
        else:
            result.append(value[i])
            i += 1
    return "".join(result)


def format_cpe(triple: CPETriple, part: str = "o") -> str:
    """Format a CPETriple back into a CPE-2.3 formatted-string.

    Round-trip equivalence: parse_cpe(format_cpe(parse_cpe(s))) == parse_cpe(s)
    """
    # Values are stored in their CPE-escaped form (backslash-colon preserved),
    # so we output them verbatim. Only bare (unescaped) colons need escaping.
    vendor = _escape_unescaped_colons(triple.vendor)
    product = _escape_unescaped_colons(triple.product)
    version = _escape_unescaped_colons(triple.version)

    # Build full 13-field CPE string, padding remaining with *.
    fields = [
        "cpe",
        "2.3",
        part,
        vendor,
        product,
        version,
        "*",  # update
        "*",  # edition
        "*",  # language
        "*",  # sw_edition
        "*",  # target_sw
        "*",  # target_hw
        "*",  # other
    ]
    return ":".join(fields)
