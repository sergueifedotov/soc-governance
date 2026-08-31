"""Integration of ML models with Phase 3 workflow.

Enhances node_propose_action with ML predictions for:
- False-positive filtering
- Severity prediction and approval gate override
- Attack pattern detection for playbook selection
"""

import logging
from typing import Any, Dict, Optional

from .feature_engineering import AlertFeatures
from .models import SeverityPredictor, FalsePositiveDetector, AttackPatternClassifier

logger = logging.getLogger(__name__)


class Phase3MLIntegration:
    """Integrate ML models with Phase 3 LangGraph workflow."""

    SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(
        self,
        severity_predictor: SeverityPredictor,
        fp_detector: FalsePositiveDetector,
        attack_classifier: AttackPatternClassifier,
    ):
        """Initialize Phase 3 ML integration.
        
        Args:
            severity_predictor: Trained SeverityPredictor model
            fp_detector: Trained FalsePositiveDetector model
            attack_classifier: Trained AttackPatternClassifier model
        """
        self.severity_predictor = severity_predictor
        self.fp_detector = fp_detector
        self.attack_classifier = attack_classifier

    async def enhance_propose_action(
        self,
        request: Dict[str, Any],
        enrichment: Dict[str, Any],
        alert_features: AlertFeatures,
        build_action_plan,  # Callable to build default action plan
    ) -> Dict[str, Any]:
        """Enhanced node_propose_action with ML context.
        
        Args:
            request: Original workflow request
            enrichment: Enrichment state (now consumed!)
            alert_features: Engineered features for the alert
            build_action_plan: Function to build default action plan
        
        Returns:
            Enhanced proposal with ML context
        """
        
        # 1. First, check if alert looks like false positive
        fp_prediction = self.fp_predictor.predict(alert_features)
        
        if fp_prediction.confidence > 0.80:
            logger.warning(
                f"Alert {alert_features.alert_id} flagged as likely false positive "
                f"({fp_prediction.confidence:.0%} confidence)"
            )
            return {
                "stage": "proposal",
                "proposed_action": "analyst_review_required",
                "reason": f"ML detected likely false positive ({fp_prediction.confidence:.0%} confidence)",
                "recommended_action": request.get("use_case", "unknown"),
                "ml_context": {
                    "false_positive_probability": fp_prediction.confidence,
                    "feature_importance": fp_prediction.feature_importance,
                },
                "require_approval": True,
                "approval_reason": "Suspected false positive - requires analyst review",
            }
        
        # 2. Predict true severity (may override user's risk_tier)
        severity_prediction = self.severity_predictor.predict(alert_features)
        original_risk_tier = request.get("risk_tier", "medium")
        predicted_risk_tier = severity_prediction.label
        
        logger.info(
            f"Predicted severity: {predicted_risk_tier} "
            f"(user said {original_risk_tier}, confidence {severity_prediction.confidence:.0%})"
        )
        
        # 3. If ML predicts higher severity, tighten approvals
        original_rank = self.SEVERITY_RANK.get(original_risk_tier, 2)
        predicted_rank = self.SEVERITY_RANK.get(predicted_risk_tier, 2)
        severity_escalation_factor = predicted_rank / original_rank if original_rank > 0 else 1.0
        
        approval_escalation = False
        escalation_reason = None
        
        if severity_escalation_factor > 1.2:
            approval_escalation = True
            escalation_reason = (
                f"ML predicts {predicted_risk_tier} (user said {original_risk_tier})"
            )
            logger.info(f"Escalating approval due to: {escalation_reason}")
        
        # 4. Build default action plan
        plan = build_action_plan(request.get("use_case", "unknown"))
        approvals_needed = plan.get("approvals_needed", 1)
        
        if approval_escalation:
            approvals_needed = int(approvals_needed * 1.5) + 1
        
        # 5. Use attack pattern classifier to identify attack type
        attack_prediction = self.attack_classifier.predict(alert_features)
        
        logger.info(
            f"Attack pattern: {attack_prediction.attack_type} "
            f"(confidence {attack_prediction.confidence:.0%})"
        )
        
        # 6. Construct enhanced proposal
        proposal = {
            "stage": "proposal",
            "proposed_action": plan.get("tool", "manual_review"),
            "action_arguments": plan.get("args", {}),
            "risk_tier": predicted_risk_tier,  # Use ML prediction
            "approvals_needed": approvals_needed,
            "ml_context": {
                "predicted_severity": predicted_risk_tier,
                "severity_confidence": severity_prediction.confidence,
                "false_positive_probability": fp_prediction.confidence,
                "attack_pattern": attack_prediction.attack_type,
                "attack_pattern_confidence": attack_prediction.confidence,
                "severity_feature_importance": severity_prediction.feature_importance,
                "approval_escalation": {
                    "escalated": approval_escalation,
                    "reason": escalation_reason,
                    "escalation_factor": float(severity_escalation_factor),
                },
            },
            "approval_reason": (
                escalation_reason
                or f"ML confirmed risk tier: {predicted_risk_tier}"
            ),
        }
        
        return proposal

    async def shadow_mode_evaluate(
        self,
        alert_features: AlertFeatures,
        analyst_label: str,  # True analyst decision after incident closed
    ) -> Dict[str, Any]:
        """Evaluate ML predictions against ground truth (shadow mode).
        
        Used during canary deployment to compare ML vs analyst labels.
        
        Args:
            alert_features: Features of the alert
            analyst_label: Final analyst determination
        
        Returns:
            Evaluation dict
        """
        severity_pred = self.severity_predictor.predict(alert_features)
        fp_pred = self.fp_detector.predict(alert_features)
        attack_pred = self.attack_classifier.predict(alert_features)
        
        return {
            "alert_id": alert_features.alert_id,
            "severity_prediction": severity_pred.label,
            "severity_analyst_label": analyst_label,
            "severity_match": severity_pred.label == analyst_label,
            "severity_confidence": severity_pred.confidence,
            "false_positive_prediction": fp_pred.is_false_positive,
            "false_positive_confidence": fp_pred.confidence,
            "attack_pattern": attack_pred.attack_type,
            "timestamp": alert_features.timestamp.isoformat(),
        }

    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all ML models.
        
        Returns:
            Status dict
        """
        return {
            "severity_predictor": {
                "fitted": self.severity_predictor.is_fitted,
                "features": len(self.severity_predictor.feature_names),
            },
            "false_positive_detector": {
                "fitted": self.fp_detector.is_fitted,
                "features": len(self.fp_detector.feature_names),
            },
            "attack_pattern_classifier": {
                "fitted": self.attack_classifier.is_fitted,
                "features": len(self.attack_classifier.feature_names),
            },
        }


def create_ml_integrated_proposal(
    request: Dict[str, Any],
    enrichment: Dict[str, Any],
    alert_features: AlertFeatures,
    ml_integration: Phase3MLIntegration,
    build_action_plan,
) -> Dict[str, Any]:
    """Helper to create ML-enhanced proposal.
    
    Can be called from Phase 3 node_propose_action:
    
        proposal = await create_ml_integrated_proposal(
            state["request"],
            state["enrichment"],
            state["alert_features"],
            ml_integration,
            _build_action_plan,
        )
        state["proposed_action"] = proposal
    
    Args:
        request: Request dict
        enrichment: Enrichment state
        alert_features: Engineered features
        ml_integration: Phase3MLIntegration instance
        build_action_plan: Action plan builder function
    
    Returns:
        Enhanced proposal dict
    """
    import asyncio
    
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(
        ml_integration.enhance_propose_action(
            request,
            enrichment,
            alert_features,
            build_action_plan,
        )
    )
