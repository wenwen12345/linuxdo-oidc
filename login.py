from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List
from dotenv import load_dotenv
import uuid
import os
import httpx
import yaml # Add yaml import
# import mysql # Removed unused import
import mysql.connector # Use this connector
import hashlib # Add hashlib import

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
    data_bytes = data.encode('utf-8')
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
            return 0 # Cannot proceed without a valid connection

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
    print(f"Generated state: {generated_state}") # Log for debugging
    return RedirectResponse(
        url=f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={os.getenv('client_id')}&state={generated_state}",
        status_code=302,
    )


@app.get("/oauth2/callback", response_class=HTMLResponse)
def callback(code: str, state: str):
    # --- State Validation ---
    print(f"Received state: {state}") # Log for debugging
    print(f"Stored states: {list(state_storage.keys())}") # Log for debugging
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

    username = response2.json()['username']
    email = f"{username}@linux.do" # Construct email using the fetched username
    password = uuid.uuid4().hex 

    conn = None
    cursor = None
    try:
        # Establish database connection using environment variables
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", 3306)), # Add port, default to 3306
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )

        if conn.is_connected():
            print("Database connection successful for callback.")

            # Get the next bind_id using the corrected function
            max_bind_id = get_max_bind_id(conn)
            next_bind_id = max_bind_id + 1

            # Use 'with' statement for cursor management
            with conn.cursor() as cursor:
                # Check if user already exists by username or email
                check_sql = "SELECT username FROM auth WHERE username = %s OR email = %s"
                cursor.execute(check_sql, (username, email))
                existing_user = cursor.fetchone()

                if not existing_user:
                    # User does not exist, insert new record
                    print(f"User {username} does not exist. Inserting new record.")
                    insert_sql = "INSERT INTO auth (username, password, email, bind_id, token) VALUES (%s, %s, %s, %s, %s)"
                    # Hash the token value as well
                    httpx.post(os.getenv("ntfy_url"), data=f"User add: {username}, Password: {password}".encode(encoding='utf-8'))
                    token_value = hash_data_sha256(f"{email}{username}")
                    values = (username, hash_data_sha256(password), email, next_bind_id, token_value)
                    cursor.execute(insert_sql, values)
                    conn.commit() # Commit the transaction
                    print(f"User {username} inserted with bind_id {next_bind_id}")
                    # Return user info upon successful insertion (excluding password)
                    return f"用户名: {username}<br>密码: {password}</br>邮箱: {email}</br>前往<a href=\"{os.getenv('chatnio_url')}\">chatnio</a>登录" # Corrected herf to href and added quotes
                else:
                    # User already exists
                    print(f"User {username} already exists. Skipping insertion.")
                    # Return success indication for existing user
                    return "<h1>用户已存在</h1>"

        else:
            print("Database connection failed in callback.")
            # Raise HTTPException for FastAPI to handle
            raise HTTPException(status_code=500, detail="Internal server error: Database connection failed")

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
        raise HTTPException(status_code=500, detail=f"Internal server error: Database operation failed ({err.errno})")
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


# --- New Endpoint for Updating Channel Secret ---
@app.post("/add_key")
async def update_channel_secret(request: AddKeyRequest = Body(...)):
    """
    Updates the secret field of a specified channel in the config file
    by appending a list of username keys.
    """
    config_path = os.getenv("config_path")
    if not config_path or not os.path.exists(config_path):
        print(f"Error: Config path '{config_path}' not found or not set in environment.")
        raise HTTPException(status_code=500, detail="Configuration file path not configured or file not found.")

    try:
        # Read the current config
        with open(config_path, 'r', encoding="utf-8") as f:
            config = yaml.safe_load(f)
            if not config or "channel" not in config:
                print("Error: Invalid config file format.")
                raise HTTPException(status_code=500, detail="Invalid configuration file format.")

        channel_found = False
        # Find the channel and update its secret
        for channel in config.get("channel", []):
            if channel.get("name") == request.channel_name:
                print(f"Found channel: {request.channel_name}")
                current_secret = channel.get("secret", "")
                # Ensure secrets are treated as a list of lines, filtering out empty lines
                secrets_list = [line for line in current_secret.splitlines() if line.strip()] if current_secret else []
                # Filter incoming keys to remove empty strings and duplicates already present
                valid_new_keys = [key for key in request.key_list if key.strip() and key not in secrets_list]
                # Combine lists and filter again to ensure no empty strings remain
                updated_secrets_list = [key for key in (secrets_list + valid_new_keys) if key.strip()]
                channel["secret"] = "\n".join(updated_secrets_list)
                channel_found = True
                print(f"Updated secret for channel '{request.channel_name}' with keys: {valid_new_keys}")
                break # Stop after finding the channel

        if not channel_found:
            print(f"Error: Channel '{request.channel_name}' not found in config.")
            raise HTTPException(status_code=404, detail=f"Channel '{request.channel_name}' not found.")

        # Write the updated config back
        with open(config_path, 'w', encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False) # Use 'w' to overwrite, sort_keys=False to preserve order
        
        # Send ntfy notification
        ntfy_url = os.getenv("ntfy_url")
        if ntfy_url:
            try:
                keys_added_str = ", ".join(request.key_list) # Join keys for the message
                message = f"User '{request.username}' added keys [{keys_added_str}] to channel '{request.channel_name}'."
                httpx.post(ntfy_url, data=message.encode('utf-8'))
                print(f"Sent ntfy notification for channel update: {request.channel_name}")
            except Exception as ntfy_err:
                # Log the error but don't fail the request just because notification failed
                print(f"Warning: Failed to send ntfy notification: {ntfy_err}")
        else:
            print("Warning: ntfy_url environment variable not set. Skipping notification.")

        print("Config file updated successfully.")
        return JSONResponse(content={"message": f"Channel '{request.channel_name}' updated successfully."}, status_code=200)

    except yaml.YAMLError as e:
        print(f"Error processing YAML file: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing configuration file: {e}")
    except IOError as e:
        print(f"File I/O error: {e}")
        raise HTTPException(status_code=500, detail=f"File operation failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during channel update: {e}")
        raise HTTPException(status_code=500, detail=f"An unexpected internal error occurred: {e}")

