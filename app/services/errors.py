class ServiceError(Exception):
    """A client-facing error. Rendered as JSON by the API error handler."""

    def __init__(self, message: str, status: int = 400, code: str | None = None):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code
