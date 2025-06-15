import firebase_admin
from firebase_admin import credentials, firestore
import os
if not firebase_admin._apps:
    cred_path = "/etc/secrets/forensiqally-firebase-adminsdk-fbsvc-6fe07c143a.json"
    if not os.path.exists(cred_path):
        raise FileNotFoundError(f"❌ Firebase credential file not found at: {cred_path}")
    cred = credentials.Certificate(cred_path)


db = firestore.client()

