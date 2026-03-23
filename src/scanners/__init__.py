from .base import BaseScanner
from .injection import InjectionScanner
from .secrets import SecretsScanner
from .auth import AuthScanner
from .xss import XSSScanner
from .dependency import DependencyScanner

ALL_SCANNERS = [
    InjectionScanner,
    SecretsScanner,
    AuthScanner,
    XSSScanner,
    DependencyScanner,
]

__all__ = ["BaseScanner", "ALL_SCANNERS"]
