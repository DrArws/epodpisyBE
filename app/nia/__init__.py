"""
NIA (Národní identitní autorita) integration package.
Provides SAML2/eIDAS identity verification for signing sessions.
"""
from app.nia.saml import NIASamlService, get_nia_service

__all__ = ["NIASamlService", "get_nia_service"]
