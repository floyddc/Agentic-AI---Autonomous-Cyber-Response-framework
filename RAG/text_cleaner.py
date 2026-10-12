import re

_REFERENCE_SECTION = re.compile(
    r"(?im)^\s{0,3}(?:#{1,6}\s*)?(?:references|bibliography|works cited|literature cited)\s*:?\s*$"
)
_REFERENCE_ENTRY = re.compile(r"(?m)^\s{0,3}\[[^\]]+\]:\s*\S.*$")
_MITRE_REFERENCE_FOOTER = re.compile(
    r"(?is)#{1,6}\s*MITRE ATT&CK Reference\b.*?\*Source:\s*MITRE ATT&CK Enterprise STIX[^*]*\*"
)
_HTML_INLINE_TAG = re.compile(r"</?(?:code|b|i|em|strong|u|span|pre)\s*>", re.IGNORECASE)
_SOURCE_CITATION = re.compile(r"\(\s*Citation:\s*[^)]*\)", re.IGNORECASE)
_NUMERIC_CITATION = re.compile(
    r"\[\^?\d+(?:\s*[-–]\s*\^?\d+)?(?:\s*[,;]\s*\^?\d+(?:\s*[-–]\s*\^?\d+)?)*\]"
)
_AUTHOR_YEAR_CITATION = re.compile(
    r"\([A-Z][A-Za-z'’.-]*(?:\s+et\s+al\.?)?,?\s+(?:19|20)\d{2}[a-z]?\)"
)


def clean_retrieval_text(text: str) -> str:
    reference_section = _REFERENCE_SECTION.search(text)
    if reference_section:
        text = text[:reference_section.start()]

    text = _REFERENCE_ENTRY.sub("", text)
    text = _MITRE_REFERENCE_FOOTER.sub("", text)
    text = _SOURCE_CITATION.sub("", text)
    text = _HTML_INLINE_TAG.sub("", text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\((?:[^()]|\([^()]*\))*\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", text)
    text = _NUMERIC_CITATION.sub("", text)
    text = re.sub(r"\[\^[\w-]+\]", "", text)
    text = _AUTHOR_YEAR_CITATION.sub("", text)
    text = re.sub(r"<https?://[^>]+>|https?://\S+", "", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\s+([,.;:!?])", r"\1", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
