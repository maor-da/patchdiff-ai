import os

os.environ["ANONYMIZED_TELEMETRY"] = "FALSE"
os.environ["CHROMA_TELEMETRY_ENABLED"] = "FALSE"

from langchain_chroma import Chroma
from common import AgentModels

from chromadb.config import Settings

settings = Settings(
    anonymized_telemetry=False,
)

class VectorStore:
    file_info = Chroma(
        persist_directory="./db",
        collection_name="windows.exe.desc",
        embedding_function=AgentModels.embedding_model.model,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
        client_settings=settings,
    )

    func_logic = Chroma(
        persist_directory="./db",
        collection_name="windows.exe.functions.logic",
        embedding_function=AgentModels.embedding_model.model,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
        client_settings=settings,
    )

    reports = Chroma(
        persist_directory="./db",
        collection_name="windows.exe.rca.reports",
        embedding_function=AgentModels.embedding_model.model,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
        client_settings=settings,
    )
