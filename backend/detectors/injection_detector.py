"""
Rule-based prompt-injection detector for NexaShield.

Design rules:
  * This module ONLY reports findings. It never blocks, allows, or decides.
    That is the job of a future policy engine.
  * Findings reuse SecurityFinding. Extra metadata (rule_id,
    injection_category, evidence) is attached via the optional fields.
  * Offsets are character offsets into the text passed in (expected to be
    normalized text — same convention as PII/secret detectors).
  * `evidence` never contains the matched prompt text. It is a bounded,
    non-sensitive summary, so POST /inspect cannot leak prompt content
    through this field.
  * Zero-width characters are substituted with spaces in a length-preserving
    parallel scan string, so a hidden attack like
    "Ignore\\u200ball\\u200bprevious\\u200binstructions" cannot evade the
    regexes while reported offsets still slice correctly from the caller's
    original `text`.
"""

from __future__ import annotations

import re

from .findings import SecurityFinding


# ---------------------------------------------------------------- rule IDs
RULE_OVERRIDE = "PI_OVERRIDE_001"
RULE_EXTRACTION = "PI_EXTRACT_001"
RULE_JAILBREAK = "PI_JAILBREAK_001"
RULE_PERSONA = "PI_PERSONA_001"
RULE_INDIRECT = "PI_INDIRECT_001"
RULE_UNFAMILIAR = "PI_UNFAMILIAR_001"


# ---------------------------------------------------------------- structural parts
_OVERRIDE_VERBS = (
    r"(?:ignore|disregard|forget|bypass|skip|drop|abandon|override|nullify|void"
    r"|discard|erase|wipe|delete|neglect|omit|set\s+aside|put\s+aside|throw\s+out)"
)
_SCOPES = (
    r"(?:all|every|any|previous|prior|above|earlier|preceding|former|system"
    r"|developer|original|initial|existing|current|past)"
)
_RULE_NOUNS = (
    r"(?:instruction|instructions|prompt|prompts|directive|directives"
    r"|guideline|guidelines|rule|rules|command|commands|constraint|constraints"
    r"|restriction|restrictions|policy|policies|guardrail|guardrails"
    r"|limit|limits|safety|filter|filters)"
)


# ---------------------------------------------------------------- override
_OVERRIDE_STRUCTURAL = re.compile(
    rf"\b{_OVERRIDE_VERBS}\b"
    r"(?:\s+\S+){0,3}?"
    rf"\s+{_SCOPES}\b"
    r"(?:\s+\S+){0,3}?"
    rf"\s+{_RULE_NOUNS}\b",
    re.IGNORECASE,
)

_OVERRIDE_EXTRAS = [
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|directives?|guidelines?|rules?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard\s+(?:everything|all)\s+(?:above|before|prior|previous)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bforget\s+(?:everything|all)\s+(?:above|before|prior|previous)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bnew\s+instructions?\s*[:\-]", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on,?\s+you\s+(?:will|must|shall)\b", re.IGNORECASE),
]


# ---------------------------------------------------------------- extraction
_EXTRACT_VERBS = (
    r"(?:reveal|show|display|print|output|repeat|tell|state|share|expose|leak"
    r"|recite|disclose|summari[sz]e|give\s+me|provide|dump)"
)
_EXTRACT_TARGETS = (
    r"(?:system\s+prompt|system\s+message|developer\s+message|developer\s+prompt"
    r"|hidden\s+prompt|initial\s+prompt|original\s+prompt|original\s+instructions?"
    r"|initial\s+instructions?|your\s+instructions?|your\s+prompt|your\s+directives?"
    r"|your\s+rules?|pre-?prompt|meta-?prompt)"
)
_EXTRACTION_PATTERNS = [
    re.compile(
        rf"\b{_EXTRACT_VERBS}\b"
        r"(?:\s+\S+){0,8}?"
        rf"\s+{_EXTRACT_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwhat\s+(?:is|are)\s+(?:your|the)\s+"
        r"(?:system|developer|hidden|initial|original)\s+"
        r"(?:prompt|message|instructions?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bprint\s+(?:your|the)\s+(?:initial|system|developer)\s+"
        r"(?:prompt|instructions?)\b",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------- jailbreak
_JAILBREAK_PATTERNS = [
    re.compile(r"\bDAN\b"),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
    re.compile(r"\bgod\s+mode\b", re.IGNORECASE),
    re.compile(r"\bunfiltered\s+mode\b", re.IGNORECASE),
    re.compile(r"\bunrestricted\s+mode\b", re.IGNORECASE),
    re.compile(r"\bno\s+restrictions?\b", re.IGNORECASE),
    re.compile(
        r"\bwithout\s+(?:any\s+)?(?:restrictions?|limitations?|filters?"
        r"|safety|guardrails?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bjailbreak(?:ed|ing)?\b", re.IGNORECASE),
    re.compile(
        r"\bpretend\s+(?:that\s+)?(?:you\s+)?(?:have\s+no|are\s+not)\s+"
        r"(?:safety|restrictions?|limitations?|filters?|guidelines?|guardrails?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bact\s+as\s+if\s+you\s+(?:have\s+no|are\s+not)\s+"
        r"(?:safety|restrictions?|limitations?|filters?|guidelines?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bbypass\s+(?:your\s+)?(?:safety|guardrails?|filters?|restrictions?"
        r"|alignment)\b",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------- persona
# Intentionally narrow. "act as a [role]" is NOT here because legitimate
# system prompts use it constantly ("act as a helpful assistant").
_PERSONA_PATTERNS = [
    re.compile(r"\bpretend\s+to\s+be\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+you\s+are\b", re.IGNORECASE),
    re.compile(r"\brole-?play\s+as\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on,?\s+you\s+are\b", re.IGNORECASE),
    re.compile(r"\bsimulate\s+being\b", re.IGNORECASE),
    re.compile(r"\bimpersonate\b", re.IGNORECASE),
]


# ---------------------------------------------------------------- indirect
# Only run against retrieved / tool blocks.
_INDIRECT_PATTERNS = [
    re.compile(
        r"\b(?:AI|assistant|model|LLM|chatbot)s?\s+"
        r"(?:must|should|shall|will\s+now)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?"
        r"(?:previous|prior|above|earlier)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:system|developer)\s+(?:override|message)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:you|the\s+assistant)\s+(?:must|should|shall)\s+"
        r"(?:now\s+)?(?:respond|reply|answer|output|say|write)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bexecute\s+the\s+following\s+(?:instructions?|commands?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:call|invoke|run)\s+(?:this|the\s+following)\s+"
        r"(?:tool|function|command)\b",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------- heuristic signals
_HEUR_RULE_REF = re.compile(
    r"\b(?:instruction|instructions|prompt|prompts|directive|directives"
    r"|guideline|guidelines|rule|rules|policy|policies|command|commands"
    r"|constraint|constraints|guardrail|guardrails|system\s+message"
    r"|developer\s+message)\b",
    re.IGNORECASE,
)
_HEUR_DIRECTIVE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|skip|drop|abandon|nullify"
    r"|void|discard|erase|wipe|delete|neglect|omit|replace|substitute"
    r"|switch\s+to|change\s+to|use|obey|follow|execute|run|perform|do|say"
    r"|respond|answer|reply|output|print|reveal|show|disclose|leak|repeat"
    r"|act|pretend|role-?play|simulate|impersonate)\b",
    re.IGNORECASE,
)
_HEUR_SECOND_PERSON = re.compile(
    r"\b(?:you|your|yours|yourself|you're|you\s+are|you\s+will|you\s+must)\b",
    re.IGNORECASE,
)
_HEUR_SCOPE_CHANGE = re.compile(
    r"\b(?:all|every|any|previous|prior|above|earlier|preceding|former"
    r"|system|developer|original|initial|existing|current|past|now|next|new)\b",
    re.IGNORECASE,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n{2,}")

# Zero-width characters that must not be able to hide an attack. Phase 2
# normalization already strips selected ZW chars from the analysis copy, but
# the detector must not depend on an upstream cleaner for a security property.
_ZW_CHARS = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


# ---------------------------------------------------------------- benign guards
# Narrow explicit benign markers. If the ±40-char window around a match
# contains one of these, suppress the finding. Not a general solution — a
# stopgap so obvious educational / game contexts do not trip rules.
_BENIGN_MARKERS = (
    "rules of chess",
    "rules of the game",
    "game rules",
    "house rules",
    "ignore the previous paragraph",
    "ignore the previous sentence",
    "ignore the previous line",
    "ignore the above formatting",
    "ignore the typo",
    "how system prompts work",
    "how prompt injection works",
    "system prompt works",
    "article discusses prompt injection",
    "research on prompt injection",
    "security research",
    "in this essay",
    "in this article",
)


def _benign_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 40) : min(len(text), end + 40)].lower()
    return any(marker in window for marker in _BENIGN_MARKERS)


def _push(
    findings: list[SecurityFinding],
    *,
    start: int,
    end: int,
    rule_id: str,
    category: str,
    severity: str,
) -> None:
    # De-duplicate exact (start, end, rule_id) — but allow different rules
    # to fire on the same span so the policy engine sees all signals.
    for f in findings:
        if f.start == start and f.end == end and f.rule_id == rule_id:
            return
    findings.append(
        SecurityFinding(
            category="prompt_injection",
            severity=severity,  # type: ignore[arg-type]
            start=start,
            end=end,
            detector="rule.injection",
            rule_id=rule_id,
            injection_category=category,
            evidence=f"{category} (rule {rule_id})",
        )
    )


def _scan(
    text: str,
    patterns,
    findings: list[SecurityFinding],
    *,
    rule_id: str,
    category: str,
    severity: str,
) -> None:
    for pat in patterns:
        for m in pat.finditer(text):
            if m.start() == m.end():
                continue
            if _benign_context(text, m.start(), m.end()):
                continue
            _push(
                findings,
                start=m.start(),
                end=m.end(),
                rule_id=rule_id,
                category=category,
                severity=severity,
            )


# ---------------------------------------------------------------- public API
def detect_injection(text: str, source: str = "user") -> list[SecurityFinding]:
    """
    Detect rule-based prompt-injection patterns in `text`.

    `source` is the block's declared source (system / user / retrieved / tool).
    It only affects whether *indirect* injection rules are applied — retrieved
    and tool content is the classic delivery channel for indirect injection.
    A caller-supplied `source` label is metadata, not proof of trust; a future
    policy engine will weigh source alongside findings.

    Returns findings sorted by (start, end, rule_id) for deterministic output.
    Offsets slice correctly against the ORIGINAL `text` argument — zero-width
    characters are substituted with spaces in a parallel scan string of the
    same length, so offsets are preserved.
    """
    if not isinstance(text, str) or not text:
        return []

    # Length-preserving substitution: every ZW char becomes a single space.
    # Regex matches run on `scan`; offsets are reported as-is and remain
    # valid slices of `text`.
    scan = _ZW_CHARS.sub(" ", text)

    findings: list[SecurityFinding] = []

    _scan(
        scan,
        [_OVERRIDE_STRUCTURAL, *_OVERRIDE_EXTRAS],
        findings,
        rule_id=RULE_OVERRIDE,
        category="override",
        severity="high",
    )

    _scan(
        scan,
        _EXTRACTION_PATTERNS,
        findings,
        rule_id=RULE_EXTRACTION,
        category="extraction",
        severity="high",
    )

    _scan(
        scan,
        _JAILBREAK_PATTERNS,
        findings,
        rule_id=RULE_JAILBREAK,
        category="jailbreak",
        severity="high",
    )

    _scan(
        scan,
        _PERSONA_PATTERNS,
        findings,
        rule_id=RULE_PERSONA,
        category="persona",
        severity="medium",
    )

    if source in ("retrieved", "tool"):
        _scan(
            scan,
            _INDIRECT_PATTERNS,
            findings,
            rule_id=RULE_INDIRECT,
            category="indirect",
            severity="high",
        )

    known_spans = [(f.start, f.end) for f in findings]

    def _overlaps_known(s: int, e: int) -> bool:
        return any(not (e <= a or s >= b) for a, b in known_spans)

    cursor = 0
    for m in _SENTENCE_SPLIT.finditer(scan):
        sentence_start, sentence_end = cursor, m.start()
        cursor = m.end()

        sentence = scan[sentence_start:sentence_end]
        if not sentence.strip():
            continue
        if _overlaps_known(sentence_start, sentence_end):
            continue
        if _benign_context(scan, sentence_start, sentence_end):
            continue

        signals = (
            bool(_HEUR_RULE_REF.search(sentence)),
            bool(_HEUR_DIRECTIVE.search(sentence)),
            bool(_HEUR_SECOND_PERSON.search(sentence)),
            bool(_HEUR_SCOPE_CHANGE.search(sentence)),
        )
        if sum(signals) < 3:
            continue

        _push(
            findings,
            start=sentence_start,
            end=sentence_end,
            rule_id=RULE_UNFAMILIAR,
            category="unfamiliar",
            severity="low",
        )

    if cursor < len(scan):
        sentence = scan[cursor:]
        if (
            sentence.strip()
            and not _overlaps_known(cursor, len(scan))
            and not _benign_context(scan, cursor, len(scan))
        ):
            signals = (
                bool(_HEUR_RULE_REF.search(sentence)),
                bool(_HEUR_DIRECTIVE.search(sentence)),
                bool(_HEUR_SECOND_PERSON.search(sentence)),
                bool(_HEUR_SCOPE_CHANGE.search(sentence)),
            )
            if sum(signals) >= 3:
                _push(
                    findings,
                    start=cursor,
                    end=len(scan),
                    rule_id=RULE_UNFAMILIAR,
                    category="unfamiliar",
                    severity="low",
                )

    findings.sort(key=lambda f: (f.start, f.end, f.rule_id or ""))
    return findings