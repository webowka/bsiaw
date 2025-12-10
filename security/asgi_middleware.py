from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.requests import Request

class AddSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware dla FastAPI/Starlette, które dopina nagłówki zapobiegające clickjackingowi.
    Domyślnie dodaje:
      X-Frame-Options: DENY
      Content-Security-Policy: frame-ancestors 'none';
    Możesz zmienić wartości przekazując inne argumenty przy rejestracji middleware.
    """
    def __init__(self, app: ASGIApp, xfo: str = "DENY", csp: str = "frame-ancestors 'none';"):
        super().__init__(app)
        self.xfo = xfo
        self.csp = csp

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Dodaj nagłówki tylko jeśli nie istnieją (umożliwia nadpisanie gdzie indziej)
        if "X-Frame-Options" not in response.headers:
            response.headers["X-Frame-Options"] = self.xfo
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = self.csp
        return response
