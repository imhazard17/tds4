import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
import httpx
from urllib.parse import urlencode
from dotenv import load_dotenv

# ─── LOAD ENV ──────────────────────────────────────────────────────────────────
load_dotenv()  # expects GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# Make sure this matches your Google console exactly:
REDIRECT_URI         = "http://localhost:8000/auth/callback"
SCOPES               = ["openid", "email"]

# ─── APP SETUP ─────────────────────────────────────────────────────────────────
app = FastAPI()


# ─── ENDPOINTS ────────────────────────────────────────────────────────────────

@app.get("/login")
async def login():
    """
    Redirects the user to Google's OAuth2 consent screen.
    """
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return RedirectResponse(url)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, error: str = None):
    """
    Handles Google's callback, exchanges 'code' for tokens,
    then sets the id_token in a secure HTTP-only cookie.
    """
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code in callback")

    # Exchange code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "grant_type":    "authorization_code",
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  REDIRECT_URI,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data)
        resp.raise_for_status()
        tokens = resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=500, detail="No id_token returned")

    # Set id_token in a secure, HTTP-only cookie
    response = JSONResponse({"status": "logged_in"})
    response.set_cookie(
        key="id_token",
        value=id_token,
        httponly=True,
        secure=False,    # set True if serving over HTTPS
        samesite="lax",
    )
    return response


@app.get("/id_token")
async def read_id_token(request: Request):
    """
    Returns the raw id_token as JSON if present;
    otherwise redirects to /login.
    """
    id_token = request.cookies.get("id_token")
    if not id_token:
        return RedirectResponse("/login")
    return JSONResponse({"id_token": id_token})
