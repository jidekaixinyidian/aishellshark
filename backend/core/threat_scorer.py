from typing import List, Optional
from backend.models.schemas import (
    ThreatScore, ThreatLevel, DetectionResult, BehaviorAlert,
    SignatureMatch, EntropyResult
)


class ThreatScorer:
    WEIGHTS = {
        "feature": 30,
        "behavior": 25,
        "entropy": 15,
        "ai": 30,
    }

    def __init__(self, config: dict = None):
        self.config = config or {}

    def score(
        self,
        session_id: str,
        detection: Optional[DetectionResult] = None,
        behavior_alerts: Optional[List[BehaviorAlert]] = None,
        entropy: Optional[EntropyResult] = None,
        ai_confidence: float = 0.0,
    ) -> ThreatScore:
        detection_score = detection.threat_score if detection else 0.0
        behavior_score = self._score_behavior(behavior_alerts or [])
        entropy_score = self._score_entropy(entropy)
        ai_score = self._score_ai(ai_confidence)
        total = min(detection_score + entropy_score + ai_score, 100.0)
        level = self._to_level(total)
        return ThreatScore(
            session_id=session_id,
            total_score=total,
            feature_score=min(detection_score, self.WEIGHTS["feature"]),
            behavior_score=behavior_score,
            entropy_score=entropy_score,
            ai_score=ai_score,
            threat_level=level,
        )

    def _score_features(self, detection_score: float) -> float:
        return min(detection_score, self.WEIGHTS["feature"])

    def _score_behavior(self, alerts: List[BehaviorAlert]) -> float:
        severity_scores = {
            ThreatLevel.LOW: 5,
            ThreatLevel.MEDIUM: 12,
            ThreatLevel.HIGH: 20,
            ThreatLevel.CRITICAL: 25,
        }
        return min(sum(severity_scores.get(a.severity, 0) for a in alerts), self.WEIGHTS["behavior"])

    def _score_entropy(self, entropy: Optional[EntropyResult]) -> float:
        if not entropy:
            return 0.0
        score = 0.0
        if entropy.is_high_entropy:
            score += 10
        if entropy.is_aes_aligned:
            score += 5
        return min(score, self.WEIGHTS["entropy"])

    def _score_ai(self, confidence: float) -> float:
        return confidence * self.WEIGHTS["ai"]

    def _to_level(self, score: float) -> ThreatLevel:
        if score >= 80:
            return ThreatLevel.CRITICAL
        if score >= 60:
            return ThreatLevel.HIGH
        if score >= 40:
            return ThreatLevel.MEDIUM
        if score >= 15:
            return ThreatLevel.LOW
        return ThreatLevel.LOW
