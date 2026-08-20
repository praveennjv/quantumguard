from scanner.languages.java import JavaAdapter
from scanner.languages.javascript import JavaScriptAdapter
from scanner.languages.python import PythonAdapter
from scanner.languages.typescript import TypeScriptAdapter

ADAPTERS = [
    PythonAdapter(),
    JavaAdapter(),
    JavaScriptAdapter(),
    TypeScriptAdapter(),
]


def adapter_for(suffix: str):
    suffix = suffix.lower()
    for adapter in ADAPTERS:
        if suffix in adapter.extensions:
            return adapter
    return None
