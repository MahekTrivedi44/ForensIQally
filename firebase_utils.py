import firebase_admin
from firebase_admin import credentials, firestore

if not firebase_admin._apps:
    cred = credentials.Certificate("forensiqally-firebase-adminsdk-fbsvc-6fe07c143a.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

