from fastapi import FastAPI, HTTPException, Header, Form
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional
from dotenv import load_dotenv
import uuid
import os
import httpx
import jwt
import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


load_dotenv()

app = FastAPI()

# --- Global Variables & Helpers ---

# WARNING: This in-memory storage is for demonstration only.
# It's not suitable for production, multi-process, or multi-instance setups.
# Use proper session management or a dedicated cache (e.g., Redis) in production.
state_storage = {}
nonce_storage = {}
access_token_storage = {}  # Store access tokens for userinfo endpoint

# OIDC Configuration
def get_base_url():
    """Get base URL from environment or use default"""
    return os.getenv("base_url", "https://test.liaowen.eu.org")

# Load RSA keys
def load_rsa_keys():
    """从环境变量加载私钥并自动生成公钥"""
    private_key_pem = os.getenv("private_key")
    if not private_key_pem:
        raise HTTPException(status_code=500, detail="未找到PRIVATE_KEY环境变量")
    
    try:
        # 从环境变量加载私钥
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None, backend=default_backend()
        )
        
        # 从私钥自动生成公钥
        public_key = private_key.public_key()
        
        return private_key, public_key
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"加载私钥失败: {str(e)}")

# Get RSA public key components for JWKS
def get_rsa_jwk():
    """Get RSA public key in JWK format"""
    _, public_key = load_rsa_keys()
    
    # Get public key numbers
    public_numbers = public_key.public_numbers()
    
    # Convert to base64url format
    def int_to_base64url(value):
        byte_length = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(byte_length, 'big')).decode('ascii').rstrip('=')
    
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "rsa-key-1",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e)
    }

# JWKS endpoint  
@app.get("/.well-known/jwks.json")
def jwks():
    """JSON Web Key Set - provides RSA public key for JWT verification"""
    try:
        jwk = get_rsa_jwk()
        return JSONResponse({
            "keys": [jwk]
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate JWKS: {str(e)}")

# OIDC Discovery endpoint
@app.get("/.well-known/openid-configuration")
def openid_configuration():
    base_url = get_base_url()
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": [
            "sub", "name", "username", "email", "picture", 
            "trust_level", "iss", "aud", "exp", "iat", "nonce"
        ]
    })

# OIDC Authorization endpoint
@app.get("/auth")
def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid",
    state: Optional[str] = None,
    nonce: Optional[str] = None
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="unsupported_response_type")
    
    if "openid" not in scope:
        raise HTTPException(status_code=400, detail="invalid_scope")
    
    # Generate state if not provided by client
    if not state:
        state = uuid.uuid4().hex
    
    # Store state and nonce for validation - use same state throughout
    state_storage[state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "nonce": nonce
    }
    
    print(f"Using state: {state}, nonce: {nonce}")
    
    # Redirect to Linux.do OAuth2 authorize endpoint using same state
    return RedirectResponse(
        url=f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={os.getenv('client_id')}&state={state}&redirect_uri={os.getenv('redirect_uri')}",
        status_code=302,
    )


# Helper function to create ID Token
def create_id_token(user_info: dict, client_id: str, nonce: Optional[str] = None):
    """Create and sign an ID Token using RS256"""
    import time
    
    base_url = get_base_url()
    now = int(time.time())
    
    payload = {
        "iss": base_url,
        "sub": str(user_info.get("id")),
        "aud": client_id,
        "exp": now + 3600,  # 1 hour
        "iat": now,
        "name": user_info.get("username"),
        "username": user_info.get("username"),
        "email": user_info.get("email"),
        "picture": user_info.get("avatar_url"),
        "trust_level": user_info.get("trust_level")
    }
    
    if nonce:
        payload["nonce"] = nonce
    
    # Load RSA private key for signing
    private_key, _ = load_rsa_keys()
    
    # Convert private key to PEM format for PyJWT
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    headers = {
        "alg": "RS256",
        "typ": "JWT", 
        "kid": "rsa-key-1"
    }
    
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    print(f"JWT payload: {payload}")
    return token

# Callback endpoint to handle Linux.do OAuth2 redirect
@app.get("/callback")
def callback(code: str, state: str):
    """Handle callback from Linux.do OAuth2 authorization"""
    print(f"Callback: received state={state}, stored states={list(state_storage.keys())}")
    
    # Validate state
    if state not in state_storage:
        print(f"State validation FAILED! Received: {state}")
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Get stored authorization request data
    auth_data = state_storage[state]
    original_redirect_uri = auth_data["redirect_uri"]
    
    # Generate new authorization code for the client
    new_code = uuid.uuid4().hex
    
    # Store the Linux.do code mapped to our new code
    code_storage = getattr(callback, 'code_storage', {})
    code_storage[new_code] = {
        "linuxdo_code": code,
        "client_id": auth_data["client_id"],
        "redirect_uri": original_redirect_uri,
        "scope": auth_data["scope"],
        "nonce": auth_data.get("nonce")
    }
    callback.code_storage = code_storage
    
    # Redirect back to the original client with our authorization code
    separator = "&" if "?" in original_redirect_uri else "?"
    final_url = f"{original_redirect_uri}{separator}code={new_code}&state={state}"
    print(f"Redirecting to: {final_url}")
    return RedirectResponse(
        url=final_url,
        status_code=302
    )

# OIDC Token endpoint
@app.post("/token")
def token_endpoint(
    grant_type: str = Form(),
    code: str = Form(),
    redirect_uri: str = Form(),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None)
):
    # if grant_type != "authorization_code":
    #     raise HTTPException(status_code=400, detail="unsupported_grant_type")
    
    
    # Get the stored code data
    code_storage = getattr(callback, 'code_storage', {})
    if code not in code_storage:
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    
    code_data = code_storage[code]
    linuxdo_code = code_data["linuxdo_code"]
    
    # Clean up used code
    del code_storage[code]
    
    # Exchange Linux.do authorization code for access token
    payload = {
        "grant_type": "authorization_code", 
        "code": linuxdo_code,
        "redirect_uri": os.getenv("redirect_uri"),
    }
    
    authlogin = httpx.BasicAuth(os.getenv("client_id"), os.getenv("client_secret")) # type: ignore
    
    try:
        print(f"Token request payload: {payload}")
        response = httpx.post(
            "https://connect.linux.do/oauth2/token", 
            data=payload, 
            auth=authlogin,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30.0
        )
        
        print(f"Linux.do token response: {response.status_code}, {response.text}")
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"invalid_grant: {response.text}")
            
        linuxdo_token_data = response.json()
        access_token = linuxdo_token_data["access_token"]
        
        # Get user info from Linux.do
        user_response = httpx.get(
            "https://connect.linux.do/api/user",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0
        )
        
        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="invalid_grant")
            
        user_info = user_response.json()
        
        # Check trust level
        min_trust_level = int(os.getenv("MIN_TRUST_LEVEL", 2))
        if user_info.get("trust_level", 0) < min_trust_level:
            raise HTTPException(status_code=403, detail="insufficient_trust_level")
        
        # Generate JWT access token for userinfo endpoint
        import time
        now = int(time.time())
        
        at_payload = {
            "iss": get_base_url(),
            "sub": str(user_info.get("id")),
            "aud": client_id or os.getenv("client_id"),
            "exp": now + 3600,
            "iat": now
        }
        
        # Load RSA private key for signing
        private_key, _ = load_rsa_keys()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,  
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        headers = {
            "alg": "RS256",
            "typ": "JWT", 
            "kid": "rsa-key-1"
        }
        
        our_access_token = jwt.encode(at_payload, private_key_pem, algorithm="RS256", headers=headers)
        
        access_token_storage[our_access_token] = {
            "user_info": user_info,
            "linuxdo_token": access_token,
            "exp": now + 3600
        }
        
        # Get nonce from code data
        nonce = code_data.get("nonce")
        
        # Create ID Token
        id_token = create_id_token(user_info, client_id or os.getenv("client_id"), nonce) # type: ignore
        
        return JSONResponse({
            "access_token": our_access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token
        })
        
    except httpx.RequestError as e:
        print(f"HTTP request error: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")
    except Exception as e:
        print(f"Unexpected error in token endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# OIDC UserInfo endpoint
@app.get("/userinfo")  
def userinfo(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    access_token = authorization.split("Bearer ")[1]
    
    try:
        # Try to decode JWT access token first
        private_key, public_key = load_rsa_keys()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Decode and verify JWT
        decoded_token = jwt.decode(access_token, public_key_pem, algorithms=["RS256"])
        
        # Verify it's a valid JWT access token (no need to check token_type field)
        
        # Get user info from storage using the original token
        if access_token not in access_token_storage:
            raise HTTPException(status_code=401, detail="Token not in storage")
        
        token_data = access_token_storage[access_token]
        user_info = token_data["user_info"]
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        # Fallback to old storage method for backward compatibility
        if access_token not in access_token_storage:
            raise HTTPException(status_code=401, detail="Invalid access token")
        
        token_data = access_token_storage[access_token]
        
        # Check if token is expired
        import time
        if int(time.time()) > token_data["exp"]:
            del access_token_storage[access_token]
            raise HTTPException(status_code=401, detail="Token expired")
        
        user_info = token_data["user_info"]
    
    # Return standardized OIDC claims
    return JSONResponse({
        "sub": str(user_info.get("id")),
        "name": user_info.get("name"),
        "username": user_info.get("username"),
        "email": user_info.get("email"), 
        "picture": user_info.get("avatar_url"),
        "trust_level": user_info.get("trust_level")
    })

