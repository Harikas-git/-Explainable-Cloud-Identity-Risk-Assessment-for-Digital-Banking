"""
Synthetic IAM Access Telemetry Generator
Generates realistic enterprise access request distributions:
- Normal routine work (Low risk)
- Remote / off-hours / new device (Medium risk / Step-up)
- Compromised credentials / impossible travel / brute force (High risk / Deny)
"""
import numpy as np
import config

def generate_synthetic_iam_dataset(n_samples: int = 2000, random_state: int = 42):
    """
    Generates synthetic access feature matrix X and risk target y (0 to 100).
    """
    rng = np.random.RandomState(random_state)
    
    # 60% routine low-risk, 25% step-up scenario, 15% high-risk attack
    n_low = int(n_samples * 0.60)
    n_med = int(n_samples * 0.25)
    n_high = n_samples - n_low - n_med

    # Low risk distribution
    low_dev_trust = rng.uniform(0.85, 1.0, n_low)
    low_ip_rep = rng.beta(1, 25, n_low) # heavily clustered near 0
    low_geo_vel = rng.exponential(15, n_low) # speeds like 5-30 km/h
    low_hour_anom = rng.beta(1, 10, n_low)
    low_res_sens = rng.choice([1, 2, 3], size=n_low, p=[0.4, 0.4, 0.2])
    low_failed = rng.choice([0, 1], size=n_low, p=[0.92, 0.08])
    low_vpn = rng.choice([1, 0], size=n_low, p=[0.85, 0.15])
    low_priv = rng.choice([0, 1], size=n_low, p=[0.95, 0.05])
    low_keystroke = rng.uniform(0.05, 0.25, n_low)
    low_risk_score = rng.uniform(5, 30, n_low)

    # Medium risk distribution (e.g. traveling employee, coffee shop, new device)
    med_dev_trust = rng.uniform(0.50, 0.85, n_med)
    med_ip_rep = rng.uniform(0.20, 0.55, n_med)
    med_geo_vel = rng.uniform(60, 450, n_med) # flight travel or fast transit
    med_hour_anom = rng.uniform(0.40, 0.75, n_med)
    med_res_sens = rng.choice([2, 3, 4], size=n_med, p=[0.3, 0.5, 0.2])
    med_failed = rng.choice([1, 2, 3], size=n_med, p=[0.6, 0.3, 0.1])
    med_vpn = rng.choice([1, 0], size=n_med, p=[0.4, 0.6])
    med_priv = rng.choice([0, 1], size=n_med, p=[0.7, 0.3])
    med_keystroke = rng.uniform(0.30, 0.65, n_med)
    med_risk_score = rng.uniform(38, 70, n_med)

    # High risk distribution (impossible travel, credential stuffing, Tor exit node)
    high_dev_trust = rng.uniform(0.0, 0.40, n_high)
    high_ip_rep = rng.uniform(0.70, 0.99, n_high)
    high_geo_vel = rng.uniform(950, 2200, n_high) # impossible velocity
    high_hour_anom = rng.uniform(0.80, 1.0, n_high)
    high_res_sens = rng.choice([3, 4, 5], size=n_high, p=[0.1, 0.3, 0.6])
    high_failed = rng.choice([4, 6, 10, 15], size=n_high, p=[0.4, 0.3, 0.2, 0.1])
    high_vpn = rng.choice([0, 1], size=n_high, p=[0.9, 0.1])
    high_priv = rng.choice([0, 1], size=n_high, p=[0.3, 0.7])
    high_keystroke = rng.uniform(0.70, 0.98, n_high)
    high_risk_score = rng.uniform(76, 99, n_high)

    # Concatenate features
    X = np.column_stack([
        np.concatenate([low_dev_trust, med_dev_trust, high_dev_trust]),
        np.concatenate([low_ip_rep, med_ip_rep, high_ip_rep]),
        np.concatenate([low_geo_vel, med_geo_vel, high_geo_vel]),
        np.concatenate([low_hour_anom, med_hour_anom, high_hour_anom]),
        np.concatenate([low_res_sens, med_res_sens, high_res_sens]),
        np.concatenate([low_failed, med_failed, high_failed]),
        np.concatenate([low_vpn, med_vpn, high_vpn]),
        np.concatenate([low_priv, med_priv, high_priv]),
        np.concatenate([low_keystroke, med_keystroke, high_keystroke])
    ])

    y = np.concatenate([low_risk_score, med_risk_score, high_risk_score])

    # Shuffle
    indices = rng.permutation(len(y))
    return X[indices], y[indices]
