# Crypto detection

Adapters produce IR call/construct nodes with resolved names, arguments, location, and snippet.

Detectors match **semantic** signals: `KeyPairGenerator.getInstance("RSA")`, `rsa.generate_private_key`, `crypto.generateKeyPairSync("rsa")`, not merely the letters "RSA" in comments.

Confidence is stored on each finding. Unexplained findings are not emitted: every hit has evidence (source snippet) and a rule id.

Language coverage MVP: Java (javalang), Python (stdlib `ast`), JavaScript/TypeScript (esprima; TS types stripped first).
