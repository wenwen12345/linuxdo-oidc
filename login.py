import json
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
import uuid
import os
import httpx

load_dotenv()

app = FastAPI()


@app.get("/")
def login():
    return RedirectResponse(
        url=f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={os.getenv('client_id')}&state={uuid.uuid4().hex}",
        status_code=302,
    )


@app.get("/oauth2/callback")
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
    if response2.json()["trust_level"] < 2:
        return 403
    email = f"{response2.json()['username']}@linux.do"
    response3 = httpx.post(
        f"{os.getenv('litellm_url')}/user/new",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('litellm_key')}",
        },
        data=json.dumps(
            {
                "user_email": email,
                "user_role": "internal_user",
                "team_id": os.getenv("team_id"),
                "models": ["PLEASE CREATE YOUR NEW VIRTUAL KEY"]
            }
        ),
    )
    if response3.status_code != 200:
        return response3.status_code
    userid = response3.json()["user_id"]
    response4 = httpx.post(
        f"{os.getenv('litellm_url')}/end_user/new",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('litellm_key')}",
        },
        data=json.dumps({"user_id": userid, "budget_id": os.getenv("budget_id")}),
    )
    if response4.status_code != 200:
        return response4.status_code
    response5 = httpx.post(
        f"{os.getenv('litellm_url')}/invitation/new",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('litellm_key')}",
        },
        data=json.dumps({"user_id": userid}),
    )
    if response5.status_code != 200:
        return response5.status_code
    return RedirectResponse(url=f"{os.getenv("litellm_url")}/ui?invitation_id={response5.json()['id']}", status_code=302)
