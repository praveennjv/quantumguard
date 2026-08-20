# Risk engine

Versioned models (`v1-algorithm-only` … `v4-business`) are stored on every finding.

RSA/ECC default to Medium/High bands, **not** Critical, unless key size, classical weakness, or (in v3+) HNDL context justifies it.

Factors: quantum vulnerability class, algorithm, key size, usage, application criticality, internet exposure, data sensitivity, data lifetime, authentication importance.

Research use: swap models without changing detectors.
