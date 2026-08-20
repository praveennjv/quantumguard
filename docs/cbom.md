# Cryptographic Bill of Materials (CBOM)

Export CycloneDX 1.6 JSON via `quantumguard scan --format cbom`.

Represented edges (MVP): application/target → libraries → cryptographic assets (algorithms) with file/line evidence.

Later: keys, certificates, protocols, and data objects as first-class cryptoProperties.
