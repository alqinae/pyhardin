from datetime import datetime


class HardinError(Exception):
    def __init__(self, message: str, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.timestamp = datetime.utcnow()


class ConfigError(HardinError):
    pass


class ScannerError(HardinError):
    pass


class AnalyzerError(HardinError):
    pass


class APIRateLimitError(AnalyzerError):
    def __init__(self, message: str = "API rate limit exceeded", retry_after: int = 60):
        super().__init__(message, code="RATE_LIMIT")
        self.retry_after = retry_after


class ReporterError(HardinError):
    pass


class StateError(HardinError):
    pass
