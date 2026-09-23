"""
Stage 2: Risk Scoring Engine
Predicts a continuous risk score R in [0, 100] from contextual feature vectors.
Supports scikit-learn Gradient Boosting / Random Forest with calibrated fallback.
"""
import os
import numpy as np

try:
    from backend import config
    from ai_models.synthetic_data import generate_synthetic_iam_dataset
except ImportError:
    import config
    from src.synthetic_data import generate_synthetic_iam_dataset

try:
    from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class RiskScoringEngine:
    """Computes a continuous risk score R in [0, 100] for a digital banking access request."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.feature_names = config.FEATURE_NAMES
        self.model = None
        self.base_risk = 30.0  # Population expected baseline risk E[R]
        self._initialize_and_train()

    def _initialize_and_train(self):
        """Trains the risk regression ensemble using synthetic enterprise telemetry."""
        X, y = generate_synthetic_iam_dataset(n_samples=2500, random_state=self.random_state)
        self.base_risk = float(np.mean(y))
        self.feature_means = np.mean(X, axis=0)

        if SKLEARN_AVAILABLE:
            self.model = GradientBoostingRegressor(
                n_estimators=100,
                learning_rate=0.08,
                max_depth=4,
                random_state=self.random_state
            )
            self.model.fit(X, y)
        else:
            # Fallback calibrated linear-polynomial proxy
            self.model = None

    def predict_risk(self, feature_vector: np.ndarray) -> float:
        """Computes calibrated risk score R in range [0, 100]."""
        x_2d = feature_vector.reshape(1, -1)
        if SKLEARN_AVAILABLE and self.model is not None:
            pred = float(self.model.predict(x_2d)[0])
        else:
            # Calibrated mathematical approximation
            dev_trust = feature_vector[0]
            ip_rep = feature_vector[1]
            geo_vel = feature_vector[2]
            hour_anom = feature_vector[3]
            res_sens = feature_vector[4]
            failed_att = feature_vector[5]
            vpn = feature_vector[6]
            priv = feature_vector[7]
            keystroke = feature_vector[8]

            # Base computation
            score = 15.0
            score += (1.0 - dev_trust) * 22.0
            score += ip_rep * 28.0
            score += min(geo_vel / 800.0, 1.5) * 25.0
            score += hour_anom * 12.0
            score += (res_sens / 5.0) * 15.0
            score += min(failed_att * 6.0, 30.0)
            score -= vpn * 12.0
            score += priv * 10.0
            score += keystroke * 14.0
            pred = float(score)

        # Clamping to valid range [0, 100]
        calibrated_score = float(np.clip(pred, 0.0, 100.0))
        return round(calibrated_score, 1)

    def get_baseline_risk(self) -> float:
        return round(self.base_risk, 1)
