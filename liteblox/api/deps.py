"""Who's calling the API: a bearer token only (never the session cookie, so no CSRF to worry about)."""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..db import get_db
from . import tokens

bearer = HTTPBearer(auto_error=False, scheme_name='token',
                    description='An API token from the Users tab or My account: `Authorization: Bearer lbx_…`')


def api_user(request: Request, creds: HTTPAuthorizationCredentials = Depends(bearer), conn=Depends(get_db)):
    if creds is None:
        raise HTTPException(status_code=401, detail='an API token is required (Authorization: Bearer lbx_…)',
                            headers={'WWW-Authenticate': 'Bearer'})
    user = tokens.authenticate(conn, creds.credentials, request.client.host if request.client else None)
    if user is None:
        raise HTTPException(status_code=401, detail='this token is unknown, revoked or expired',
                            headers={'WWW-Authenticate': 'Bearer'})
    return user


def api_writer(user: tokens.ApiUser = Depends(api_user)):
    if user.scope != 'full':
        raise HTTPException(status_code=403, detail='this token is read-only')
    if not user.is_admin:
        raise HTTPException(status_code=403, detail='admin role required')
    return user
