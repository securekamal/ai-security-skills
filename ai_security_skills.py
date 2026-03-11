"""
ai_security_skills — Offensive & Defensive Security Toolkit for AI/LLM Systems
Author: securekamal
"""

import re
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class DetectionResult:
    risk_score: float
    risk_level: RiskLevel
    techniques: list[str] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = "ALLOW"
    raw_matches: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────
#  INJECTION DETECTOR
# ─────────────────────────────────────────────

INJECTION_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions)",
        r"forget\s+everything\s+(you\s+were\s+told|above)",
    ],
    "role_hijack": [
        r"you\s+are\s+now\s+(a|an)\s+\w+\s+(without\s+restrictions|that\s+can)",
        r"act\s+as\s+(DAN|evil|unfiltered|unrestricted)",
        r"pretend\s+(you\s+have\s+no|you\s+don't\s+have\s+any)\s+(rules|restrictions|guidelines)",
    ],
    "system_prompt_exfil": [
        r"(print|output|repeat|show|reveal)\s+(your\s+)?(system\s+prompt|instructions|configuration)",
        r"what\s+(are|were)\s+your\s+(initial|original|system)\s+instructions",
        r"tell\s+me\s+(everything\s+in\s+)?your\s+context",
    ],
    "jailbreak_framing": [
        r"(hypothetically|in\s+fiction|in\s+a\s+story|imagine)\s+.*\s+(how\s+to|explain\s+how)",
        r"for\s+(research|educational)\s+purposes\s+only",
        r"as\s+a\s+character\s+who\s+has\s+no\s+ethics",
    ],
    "indirect_injection": [
        r"<\s*(script|iframe|img)[^>]*>",
        r"\[\[inject\]\]|\[SYSTEM\]|\[ADMIN\]",
        r"---\s*SYSTEM\s*---",
    ],
    "tool_abuse": [
        r"use\s+(the\s+)?(browser|terminal|shell|python)\s+to\s+(download|execute|run)",
        r"call\s+(the\s+)?api\s+.*\s+(exfil|send\s+to|post\s+to)",
        r"execute\s+(this\s+)?(command|code|script)",
    ],
}


class InjectionDetector:
    """Runtime prompt injection detector using pattern + semantic heuristics."""

    def __init__(self, sensitivity: float = 0.5):
        self.sensitivity = sensitivity

    def scan(self, user_input: str, system_prompt: str = "") -> DetectionResult:
        text = user_input.lower()
        matches = []
        techniques_hit = []
        score = 0.0

        for technique, patterns in INJECTION_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    techniques_hit.append(technique)
                    matches.append(pat)
                    score += 0.25
                    break

        # Heuristic: unusually long system-prompt-like structure in user turn
        if len(user_input) > 800 and user_input.count("\n") > 10:
            score += 0.15
            techniques_hit.append("large_structured_input")

        # Heuristic: base64 blob (possible encoded injection)
        if re.search(r"[A-Za-z0-9+/]{60,}={0,2}", user_input):
            score += 0.10
            techniques_hit.append("encoded_content")

        score = min(score, 1.0)

        if score >= 0.75:
            level = RiskLevel.CRITICAL
            rec = "BLOCK"
        elif score >= 0.50:
            level = RiskLevel.HIGH
            rec = "BLOCK"
        elif score >= 0.25:
            level = RiskLevel.MEDIUM
            rec = "REVIEW"
        elif score > 0:
            level = RiskLevel.LOW
            rec = "LOG"
        else:
            level = RiskLevel.SAFE
            rec = "ALLOW"

        return DetectionResult(
            risk_score=round(score, 2),
            risk_level=level,
            techniques=list(set(techniques_hit)),
            explanation=f"Matched {len(set(techniques_hit))} injection technique(s).",
            recommendation=rec,
            raw_matches=matches,
        )


# ─────────────────────────────────────────────
#  OUTPUT VALIDATOR
# ─────────────────────────────────────────────

SENSITIVE_OUTPUT_PATTERNS = [
    (r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "Private Key"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa Card Number"),
    (r"password\s*[:=]\s*\S+", "Password in Output"),
    (r"(SELECT|INSERT|DROP|UPDATE)\s+\w+", "SQL in Output"),
    (r"<script[^>]*>.*?</script>", "XSS in Output"),
]


class OutputValidator:
    """Validates LLM output for sensitive data leakage and policy violations."""

    def scan(self, llm_output: str) -> DetectionResult:
        findings = []
        score = 0.0

        for pattern, label in SENSITIVE_OUTPUT_PATTERNS:
            if re.search(pattern, llm_output, re.IGNORECASE | re.DOTALL):
                findings.append(label)
                score += 0.30

        score = min(score, 1.0)
        level = RiskLevel.CRITICAL if score >= 0.5 else (RiskLevel.HIGH if score > 0 else RiskLevel.SAFE)

        return DetectionResult(
            risk_score=round(score, 2),
            risk_level=level,
            techniques=findings,
            explanation=f"Output contains {len(findings)} sensitive pattern(s).",
            recommendation="BLOCK" if score >= 0.5 else ("REDACT" if score > 0 else "ALLOW"),
        )


# ─────────────────────────────────────────────
#  RAG INTEGRITY CHECKER
# ─────────────────────────────────────────────

class RAGIntegrityChecker:
    """Detects adversarially poisoned documents in a RAG vector store."""

    def __init__(self):
        self.known_hashes: dict[str, str] = {}

    def register(self, doc_id: str, content: str):
        self.known_hashes[doc_id] = hashlib.sha256(content.encode()).hexdigest()

    def verify(self, doc_id: str, content: str) -> bool:
        expected = self.known_hashes.get(doc_id)
        actual = hashlib.sha256(content.encode()).hexdigest()
        return expected == actual

    def scan_chunk(self, chunk: str) -> DetectionResult:
        """Heuristically detect adversarial injection in a retrieved RAG chunk."""
        score = 0.0
        findings = []

        # Hidden instruction patterns in documents
        hidden_patterns = [
            (r"<!--.*?ignore.*?-->", "HTML comment injection"),
            (r"\[INST\].*?\[/INST\]", "Llama instruction tag"),
            (r"<\|system\|>|<\|user\|>|<\|assistant\|>", "ChatML token injection"),
            (r"IGNORE PREVIOUS", "Explicit override"),
            (r"SYSTEM OVERRIDE", "System override attempt"),
        ]

        for pat, label in hidden_patterns:
            if re.search(pat, chunk, re.IGNORECASE | re.DOTALL):
                findings.append(label)
                score += 0.35

        score = min(score, 1.0)
        level = RiskLevel.CRITICAL if score >= 0.5 else (RiskLevel.MEDIUM if score > 0 else RiskLevel.SAFE)

        return DetectionResult(
            risk_score=round(score, 2),
            risk_level=level,
            techniques=findings,
            recommendation="QUARANTINE" if score >= 0.5 else "ALLOW",
        )


# ─────────────────────────────────────────────
#  JAILBREAK CATALOG
# ─────────────────────────────────────────────

JAILBREAK_TECHNIQUES = {
    "DAN": "Do Anything Now — role-play as an unconstrained AI",
    "STAN": "Strive To Avoid Norms — variant of DAN",
    "AIM": "Always Intelligent and Machiavellian — evil AI persona",
    "developer_mode": "Pretend developer mode disables safety filters",
    "token_smuggling": "Unicode lookalikes to bypass keyword filters",
    "context_overflow": "Flood context to push system prompt out of attention window",
    "base64_encoding": "Encode harmful request in base64 to bypass filters",
    "roleplay_fiction": "Fictional framing to lower model guard",
    "virtual_scenario": "Ask model to simulate a system that allows anything",
    "incremental_escalation": "Start benign, gradually escalate request",
    "many_shot": "Provide many examples of harmful completions to set pattern",
    "competing_objectives": "Exploit tension between helpfulness and safety",
}


def list_jailbreak_techniques() -> dict:
    return JAILBREAK_TECHNIQUES


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AI Security Skills CLI")
    parser.add_argument("--mode", choices=["detect", "validate", "rag", "jailbreaks"], required=True)
    parser.add_argument("--input", type=str, help="Input text or file path")
    args = parser.parse_args()

    text = args.input or ""
    if text.endswith(".txt"):
        with open(text) as f:
            text = f.read()

    if args.mode == "detect":
        result = InjectionDetector().scan(text)
        print(json.dumps(result.__dict__, indent=2, default=str))

    elif args.mode == "validate":
        result = OutputValidator().scan(text)
        print(json.dumps(result.__dict__, indent=2, default=str))

    elif args.mode == "rag":
        result = RAGIntegrityChecker().scan_chunk(text)
        print(json.dumps(result.__dict__, indent=2, default=str))

    elif args.mode == "jailbreaks":
        for name, desc in list_jailbreak_techniques().items():
            print(f"  [{name}] {desc}")
