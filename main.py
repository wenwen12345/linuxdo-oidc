from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel
from typing import List
from dotenv import load_dotenv
import uuid
import os
import httpx

# import mysql # Removed unused import
import mysql.connector  # Use this connector
import hashlib  # Add hashlib import

load_dotenv()

app = FastAPI()




# --- Global Variables & Helpers ---

# WARNING: This in-memory storage is for demonstration only.
# It's not suitable for production, multi-process, or multi-instance setups.
# Use proper session management or a dedicated cache (e.g., Redis) in production.
state_storage = {}

@app.get("/linuxdo/login")
def login():
    generated_state = uuid.uuid4().hex
    state_storage[generated_state] = True  # Store the state
    print(f"Generated state: {generated_state}")  # Log for debugging
    return RedirectResponse(
        url=f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={os.getenv('client_id')}&state={generated_state}",
        status_code=302,
    )


@app.get("/oauth2/callback", response_class=HTMLResponse)
def callback(code: str, state: str):

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": os.getenv("redirect_uri"),
    }
    authlogin = httpx.BasicAuth(os.getenv("client_id"), os.getenv("client_secret"))
    response = httpx.post(
        "https://connect.linux.do/oauth2/token", data=payload, auth=authlogin
    )
    if response.status_code != 200:
        return response.status_code
    access_token = response.json()["access_token"]
    print(access_token)
    response2 = httpx.get(
        "https://connect.linux.do/api/user",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if response2.status_code != 200:
        return response2.status_code
    if response2.json()["trust_level"] < os.getenv("MIN_TRUST_LEVEL", 2):
        return 403
    print(response2.json())