from __future__ import annotations

import os

from .feature_builder import build_features


class ModelLoader:
    """
    Optional ML wrapper with a deterministic heuristic fallback.
    The fallback keeps the application usable even without scikit-learn/joblib.
    """

    def __init__(self, model_path: str = "exploit_model.pkl"):
        self.model_path = model_path
        self.model = None
        self._try_load_model()

    def _try_load_model(self) -> None:
        try:
            import joblib
        except Exception:
            self.model = None
            return

        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

    def predict(self, vuln) -> float:
        features = build_features(vuln)
        if self.model is not None:
            try:
                if hasattr(self.model, "predict_proba"):
                    probability = float(max(self.model.predict_proba([features])[0]))
                    return round(probability * 100, 2)
                prediction = self.model.predict([features])[0]
                return float(prediction)
            except Exception:
                pass

        # Heuristic fallback in the same 0-100 scale used by the UI.
        cvss_component = min(float(vuln.cvss_score) * 8.0, 80.0)
        exposure_bonus = 10.0 if vuln.network_exposed else 0.0
        exploit_bonus = 10.0 if vuln.exploit_available else 0.0
        auth_penalty = -5.0 if vuln.authentication_required else 0.0
        return round(max(0.0, min(100.0, cvss_component + exposure_bonus + exploit_bonus + auth_penalty)), 2)
