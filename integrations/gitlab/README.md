GitLab CI integration will wrap the same CLI:

```yaml
quantumguard:
  image: python:3.12
  script:
    - pip install .
    - quantumguard scan . --format sarif --fail-on high
```
