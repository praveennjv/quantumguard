FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY scanner ./scanner
RUN pip install --no-cache-dir .
ENTRYPOINT ["quantumguard"]
CMD ["scan", ".", "--fail-on", "high"]
