.PHONY: test lint scan install

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest

lint:
	python -m ruff check scanner

scan:
	python -m scanner.cli.main scan . --format json --fail-on never
