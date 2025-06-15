import os
import firebase_admin
from firebase_admin import credentials, firestore

cred_path = os.getenv("FIREBASE_CRED_PATH", "/etc/secrets/forensiqally-firebase-adminsdk-fbsvc-6fe07c143a.json")

if not os.path.exists(cred_path):
    raise FileNotFoundError(f"❌ Firebase credential not found at: {cred_path}")

if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()
