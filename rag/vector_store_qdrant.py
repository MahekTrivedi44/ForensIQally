# # NORMAL:

# # import faiss
# # import numpy as np
# # from sentence_transformers import SentenceTransformer
# # from rag.mitre_loader import load_mitre_attack_docs

# # class ThreatRAG:
# #     def __init__(self):
# #         self.model = SentenceTransformer("all-MiniLM-L6-v2")
# #         self.docs = load_mitre_attack_docs()
# #         self.embeddings = self.model.encode(self.docs, show_progress_bar=False)
# #         self.index = faiss.IndexFlatL2(self.embeddings.shape[1])
# #         self.index.add(np.array(self.embeddings))

# #     def search(self, log_lines, top_k=5):
# #         results = []
# #         queries = log_lines[:10]  # top 10 lines only
# #         query_embeddings = self.model.encode(queries)

# #         for emb in query_embeddings:
# #             _, indices = self.index.search(np.array([emb]), top_k)
# #             for i in indices[0]:
# #                 results.append(self.docs[i])

# #         return "\n".join(sorted(set(results)))  # deduplicated, sorted


# # WITH CACHING

# import faiss
# import numpy as np
# import streamlit as st
# from sentence_transformers import SentenceTransformer
# from rag.mitre_loader import load_mitre_attack_docs

# @st.cache_resource(show_spinner="🔍 Loading RAG model...")
# def get_embedding_model():
#     return SentenceTransformer("all-MiniLM-L6-v2")

# @st.cache_resource
# def get_vector_index():
#     model = get_embedding_model()
#     docs = load_mitre_attack_docs()
#     embeddings = model.encode(docs, show_progress_bar=False)

#     index = faiss.IndexFlatL2(embeddings.shape[1])
#     index.add(np.array(embeddings))

#     return model, index, docs

# class ThreatRAG:
#     def __init__(self):
#         self.model, self.index, self.docs = get_vector_index()

#     def search(self, log_lines, top_k=5):
#         results = []
#         queries = log_lines[:10]  # top 10 lines only
#         query_embeddings = self.model.encode(queries)

#         for emb in query_embeddings:
#             _, indices = self.index.search(np.array([emb]), top_k)
#             for i in indices[0]:
#                 results.append(self.docs[i])

#         return "\n".join(sorted(set(results)))  # deduplicated, sorted
import os
import uuid
import hashlib
import numpy as np
import streamlit as st
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer
from rag.mitre_loader import load_mitre_attack_docs

# --- Load environment variables ---
load_dotenv()
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")
QDRANT_URL = os.getenv("QDRANT_URL")
COLLECTION_NAME = "mitre_attack"
TOP_K = 5
BATCH_SIZE = 50

# --- Lazy-load model + Qdrant client ---

@st.cache_resource(show_spinner="🔌 Connecting to Qdrant...")
def get_qdrant_client():
    return QdrantClient(
        url=QDRANT_URL,
        api_key=QDRANT_API_KEY,
        timeout=30  # ⏱ increase timeout from default 5s → 30s
    )


@st.cache_resource(show_spinner="🧠 Loading embedding model...")
def get_model():
    return SentenceTransformer("all-MiniLM-L6-v2")

# --- Cache MITRE embeddings only once ---
@st.cache_resource(show_spinner="📚 Loading MITRE ATT&CK data...")
def get_mitre_embeddings():
    docs = load_mitre_attack_docs()
    model = get_model()
    embeddings = model.encode(docs, batch_size=64, show_progress_bar=True)
    return docs, embeddings

# --- Create collection if not already there ---
@st.cache_resource
def create_collection_if_not_exists():
    client = get_qdrant_client()
    if COLLECTION_NAME not in [col.name for col in client.get_collections().collections]:
        client.create_collection(
            COLLECTION_NAME,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE)
        )

# --- Unique cache key per log input ---
def get_log_hash(log_lines):
    joined = "\n".join(log_lines[:10])
    return hashlib.md5(joined.encode()).hexdigest()

# --- Build index but skip if already cached ---
@st.cache_resource(show_spinner="Building filtered index...")
def build_index_once(log_hash, log_lines):
    build_filtered_index(log_lines)
    return True

def build_filtered_index(log_lines):
    model = get_model()
    client = get_qdrant_client()
    all_docs, doc_embeddings = get_mitre_embeddings()

    log_embed = model.encode(" ".join(log_lines[:10]))
    scores = np.dot(doc_embeddings, log_embed)
    top_indices = scores.argsort()[-10:][::-1]  # top 10 only

    create_collection_if_not_exists()

    points = [
        PointStruct(
            id=str(uuid.uuid4()),
            vector=doc_embeddings[i].tolist(),
            payload={"text": all_docs[i]}
        )
        for i in top_indices
    ]

    for i in range(0, len(points), BATCH_SIZE):
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=points[i:i + BATCH_SIZE]
        )

class ThreatRAG:
    def __init__(self, log_lines):
        self.log_lines = log_lines  # Store for use later, but do not upsert

    def search(self, log_lines, top_k=TOP_K):
        try:
            client = get_qdrant_client()
            model = get_model()
            query_vec = model.encode(" ".join(log_lines[:10]))
            results = client.search(
                collection_name=COLLECTION_NAME,
                query_vector=query_vec,
                limit=top_k
            )
            return "\n".join(sorted(set(hit.payload['text'] for hit in results)))
        except Exception as e:
            print("[QDRANT SEARCH ERROR]", e)
            return ""
        
    def search(self, log_lines, top_k=TOP_K):
        client = get_qdrant_client()
        model = get_model()
        query_vec = model.encode(" ".join(log_lines[:10]))
        results = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_vec,
            limit=top_k
        )
        return "\n".join(sorted(set(hit.payload["text"] for hit in results)))
