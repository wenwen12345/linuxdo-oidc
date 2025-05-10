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


# --- Pydantic Models ---
class AddKeyRequest(BaseModel):
    key_list: List[str]
    username: str
    channel_name: str


# --- Global Variables & Helpers ---

# WARNING: This in-memory storage is for demonstration only.
# It's not suitable for production, multi-process, or multi-instance setups.
# Use proper session management or a dedicated cache (e.g., Redis) in production.
state_storage = {}


def hash_data_sha256(data: str) -> str:
    """
    Hashes the input string using SHA-256.

    Args:
        data: The string data to hash.

    Returns:
        The hexadecimal representation of the SHA-256 hash.
    """
    # Ensure the input is encoded to bytes, UTF-8 is standard
    data_bytes = data.encode("utf-8")
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256(data_bytes)
    # Get the hexadecimal representation of the hash
    return sha256_hash.hexdigest()


def get_max_bind_id(conn: mysql.connector.MySQLConnection) -> int:
    """
    Queries the database to get the maximum bind_id from the auth table.

    Args:
        conn: An active mysql.connector database connection.

    Returns:
        The maximum bind_id found, or 0 if the table is empty or an error occurs.
    """
    max_bind_id = 0
    cursor = None
    try:
        if not conn or not conn.is_connected():
            print("Error: Database connection is not active.")
            return 0  # Cannot proceed without a valid connection

        cursor = conn.cursor()
        cursor.execute("SELECT MAX(bind_id) FROM auth")
        result = cursor.fetchone()
        # Handle case where table is empty (MAX returns NULL)
        if result and result[0] is not None:
            max_bind_id = int(result[0])
        print(f"Max bind_id found: {max_bind_id}")
    except mysql.connector.Error as err:
        print(f"Error fetching max bind_id: {err}")
        # Return 0 on error, as per original logic's apparent intent
        max_bind_id = 0
    except Exception as e:
        print(f"An unexpected error occurred while fetching max bind_id: {e}")
        max_bind_id = 0
    finally:
        # Ensure the cursor is closed if it was opened
        if cursor:
            cursor.close()
            print("Cursor closed.")
    return max_bind_id


@app.get("/login")
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
    # --- State Validation ---
    print(f"Received state: {state}")  # Log for debugging
    print(f"Stored states: {list(state_storage.keys())}")  # Log for debugging
    if state not in state_storage:
        print("Error: Invalid state parameter")
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    # State is valid, remove it as it's single-use
    del state_storage[state]
    print("State verified successfully.")
    # --- End State Validation ---

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

    username = response2.json()["username"]
    email = f"{username}@linux.do"  # Construct email using the fetched username
    password = response2.json()["api_key"]
    # 将密码通过SHA256哈希并截取前30位
    hashed_password_full = hashlib.sha256(password.encode('utf-8')).hexdigest()
    password = hashed_password_full[:30]

    conn = None
    cursor = None
    try:
        # Establish database connection using environment variables
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", 3306)),  # Add port, default to 3306
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
        )

        if conn.is_connected():
            print("Database connection successful for callback.")

            # Get the next bind_id using the corrected function
            max_bind_id = get_max_bind_id(conn)
            next_bind_id = max_bind_id + 1

            # Use 'with' statement for cursor management
            with conn.cursor() as cursor:
                # Check if user already exists by username or email
                check_sql = (
                    "SELECT username FROM auth WHERE username = %s OR email = %s"
                )
                cursor.execute(check_sql, (username, email))
                existing_user = cursor.fetchone()

                if not existing_user:
                    # User does not exist, insert new record
                    print(f"User {username} does not exist. Inserting new record.")
                    insert_sql = "INSERT INTO auth (username, password, email, bind_id, token) VALUES (%s, %s, %s, %s, %s)"
                    # Hash the token value as well
                    httpx.post(
                        os.getenv("ntfy_url"),
                        data=f"User add: {username}, Password: {password}".encode(
                            encoding="utf-8"
                        ),
                    )
                    token_value = hash_data_sha256(f"{email}{username}")
                    values = (
                        username,
                        hash_data_sha256(password),
                        email,
                        next_bind_id,
                        token_value,
                    )
                    cursor.execute(insert_sql, values)
                    conn.commit()  # Commit the transaction
                    print(f"User {username} inserted with bind_id {next_bind_id}")
                    # Return user info upon successful insertion (excluding password)
                    return f'用户名: {username}<br>密码: {password}</br>邮箱: {email}'  # Corrected herf to href and added quotes
                else:
                    # User already exists - update password
                    print(f"User {username} already exists. Updating password.")
                    update_sql = "UPDATE auth SET password = %s WHERE username = %s"
                    cursor.execute(update_sql, (hash_data_sha256(password), username))
                    conn.commit()
                    # Return success indication for existing user with updated password
                    return "<h1>用户密码已更新</h1>"f'用户名: {username}<br>新密码: {password}</br>邮箱: {email}'

        else:
            print("Database connection failed in callback.")
            # Raise HTTPException for FastAPI to handle
            raise HTTPException(
                status_code=500,
                detail="Internal server error: Database connection failed",
            )

    except mysql.connector.Error as err:
        print(f"Database error during callback: {err}")
        # Rollback transaction in case of database error
        if conn and conn.is_connected():
            try:
                conn.rollback()
                print("Transaction rolled back due to database error.")
            except mysql.connector.Error as rollback_err:
                print(f"Error during rollback: {rollback_err}")
        # Raise HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: Database operation failed ({err.errno})",
        )
    except Exception as e:
        print(f"An unexpected error occurred during callback db operations: {e}")
        # Raise HTTPException for unexpected errors
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
    finally:
        # Ensure cursor and connection are closed
        if cursor:
            cursor.close()
            print("Callback cursor closed.")
        if conn and conn.is_connected():
            conn.close()
            print("Callback database connection closed.")