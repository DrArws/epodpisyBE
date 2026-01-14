import subprocess
from fastapi import HTTPException

def get_google_id_token() -> str:
    """
    Retrieves a Google ID token using the gcloud CLI.
    Assumes the user is already authenticated.
    """
    try:
        # Print the identity token
        token_process = subprocess.run(
            ["gcloud", "auth", "print-identity-token"],
            capture_output=True,
            text=True,
            check=True,
        )
        return token_process.stdout.strip()
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="gcloud CLI not found. Please install the Google Cloud SDK.",
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get Google ID token: {e.stderr}",
        )
