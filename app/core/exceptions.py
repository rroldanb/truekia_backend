from fastapi import HTTPException, status

class BaseAPIException(HTTPException):
    """Base exception class for API errors"""
    def __init__(self, detail: str = None, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.status_code = status_code
        self.detail = detail or "An error occurred"
        super().__init__(status_code=status_code, detail=self.detail)


class BadRequestException(BaseAPIException):
    """400 Bad Request"""
    def __init__(self, detail: str = "Bad request"):
        super().__init__(detail=detail, status_code=status.HTTP_400_BAD_REQUEST)


class UnauthorizedException(BaseAPIException):
    """401 Unauthorized"""
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)


class ForbiddenException(BaseAPIException):
    """403 Forbidden"""
    def __init__(self, detail: str = "Access forbidden"):
        super().__init__(detail=detail, status_code=status.HTTP_403_FORBIDDEN)


class NotFoundException(BaseAPIException):
    """404 Not Found"""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(detail=detail, status_code=status.HTTP_404_NOT_FOUND)


class ConflictException(BaseAPIException):
    """409 Conflict"""
    def __init__(self, detail: str = "Resource conflict"):
        super().__init__(detail=detail, status_code=status.HTTP_409_CONFLICT)


class UnprocessableEntityException(BaseAPIException):
    """422 Unprocessable Entity"""
    def __init__(self, detail: str = "Unprocessable entity"):
        super().__init__(detail=detail, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


class TooManyRequestsException(BaseAPIException):
    """429 Too Many Requests"""
    def __init__(self, detail: str = "Too many requests"):
        super().__init__(detail=detail, status_code=status.HTTP_429_TOO_MANY_REQUESTS)


class InternalServerErrorException(BaseAPIException):
    """500 Internal Server Error"""
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(detail=detail, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Business logic specific exceptions
class UserNotFoundException(NotFoundException):
    """User not found exception"""
    def __init__(self, user_id: int = None):
        detail = f"User with ID {user_id} not found" if user_id else "User not found"
        super().__init__(detail=detail)


class UserAlreadyExistsException(ConflictException):
    """User already exists exception"""
    def __init__(self, email: str = None):
        detail = f"User with email {email} already exists" if email else "User already exists"
        super().__init__(detail=detail)


class InvalidCredentialsException(UnauthorizedException):
    """Invalid credentials exception"""
    def __init__(self, detail: str = "Invalid email or password"):
        super().__init__(detail=detail)


class TokenExpiredException(UnauthorizedException):
    """Token expired exception"""
    def __init__(self, detail: str = "Token has expired"):
        super().__init__(detail=detail)


class InvalidTokenException(UnauthorizedException):
    """Invalid token exception"""
    def __init__(self, detail: str = "Invalid token"):
        super().__init__(detail=detail)


class InsufficientPermissionsException(ForbiddenException):
    """Insufficient permissions exception"""
    def __init__(self, detail: str = "Insufficient permissions to perform this action"):
        super().__init__(detail=detail)


class AccountInactiveException(ForbiddenException):
    """Account inactive exception"""
    def __init__(self, detail: str = "Account is inactive"):
        super().__init__(detail=detail)


class EmailNotVerifiedException(ForbiddenException):
    """Email not verified exception"""
    def __init__(self, detail: str = "Email address not verified"):
        super().__init__(detail=detail)


class ValidationException(UnprocessableEntityException):
    """Custom validation exception"""
    def __init__(self, field: str, message: str):
        detail = f"Validation error for field '{field}': {message}"
        super().__init__(detail=detail)


class DatabaseException(InternalServerErrorException):
    """Database operation exception"""
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(detail=detail)


class FileUploadException(BadRequestException):
    """File upload exception"""
    def __init__(self, detail: str = "File upload failed"):
        super().__init__(detail=detail)


class FileSizeException(BadRequestException):
    """File size exceeded exception"""
    def __init__(self, max_size: int):
        detail = f"File size exceeds maximum allowed size of {max_size} bytes"
        super().__init__(detail=detail)


class FileTypeException(BadRequestException):
    """Invalid file type exception"""
    def __init__(self, allowed_types: list):
        detail = f"Invalid file type. Allowed types: {', '.join(allowed_types)}"
        super().__init__(detail=detail)


class RateLimitException(TooManyRequestsException):
    """Rate limit exceeded exception"""
    def __init__(self, detail: str = "Rate limit exceeded. Please try again later"):
        super().__init__(detail=detail)


class MaintenanceModeException(BaseAPIException):
    """Maintenance mode exception"""
    def __init__(self, detail: str = "Service is currently under maintenance"):
        super().__init__(detail=detail, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


# Trading platform specific exceptions
class TransactionNotFoundException(NotFoundException):
    """Transaction not found exception"""
    def __init__(self, transaction_id: int = None):
        detail = f"Transaction with ID {transaction_id} not found" if transaction_id else "Transaction not found"
        super().__init__(detail=detail)


class InsufficientBalanceException(BadRequestException):
    """Insufficient balance exception"""
    def __init__(self, detail: str = "Insufficient balance for this transaction"):
        super().__init__(detail=detail)


class MessageNotFoundException(NotFoundException):
    """Message not found exception"""
    def __init__(self, message_id: int = None):
        detail = f"Message with ID {message_id} not found" if message_id else "Message not found"
        super().__init__(detail=detail)


class ConversationNotFoundException(NotFoundException):
    """Conversation not found exception"""
    def __init__(self, conversation_id: int = None):
        detail = f"Conversation with ID {conversation_id} not found" if conversation_id else "Conversation not found"
        super().__init__(detail=detail)


class UnauthorizedMessageAccessException(ForbiddenException):
    """Unauthorized message access exception"""
    def __init__(self, detail: str = "You don't have permission to access this message"):
        super().__init__(detail=detail)


class BlockedUserException(ForbiddenException):
    """Blocked user exception"""
    def __init__(self, detail: str = "This user has been blocked"):
        super().__init__(detail=detail)


class InvalidTransactionStatusException(BadRequestException):
    """Invalid transaction status exception"""
    def __init__(self, current_status: str, attempted_status: str):
        detail = f"Cannot change transaction status from {current_status} to {attempted_status}"
        super().__init__(detail=detail)