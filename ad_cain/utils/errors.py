"""Custom exceptions for AD-Cain."""


class ADCainError(Exception):
    """Base exception for all AD-Cain errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class LDAPConnectionError(ADCainError):
    """Failed to connect to LDAP server."""


class LDAPOperationError(ADCainError):
    """LDAP operation (search/create/modify/delete) failed."""

    def __init__(self, message: str, operation: str = "", dn: str = "", details: dict | None = None):
        super().__init__(message, details)
        self.operation = operation
        self.dn = dn


class SchemaValidationError(ADCainError):
    """State file failed schema validation."""

    def __init__(self, message: str, validation_errors: list | None = None, details: dict | None = None):
        super().__init__(message, details)
        self.validation_errors = validation_errors or []


class DependencyError(ADCainError):
    """Circular or unresolvable dependency between AD objects."""


class SYSVOLError(ADCainError):
    """Error reading or writing SYSVOL files."""


class ExportError(ADCainError):
    """Error during AD state export."""


class RestorationError(ADCainError):
    """Error during AD state restoration/import."""

    def __init__(self, message: str, failed_objects: list | None = None, details: dict | None = None):
        super().__init__(message, details)
        self.failed_objects = failed_objects or []
