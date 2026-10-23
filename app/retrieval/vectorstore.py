"""向量存储的后端抽象。

默认 numpy 后端：单文件 .npy + ids.json，零外部依赖、启动即用、10w 片段以内毫秒级。
生产后端：Qdrant（docker-compose 里有），实现同一套接口，改一个环境变量即可切换。
这一层抽象本身就是面试考点：为什么要隔离存储层。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

import numpy as np


@runtime_checkable
class VectorStore(Protocol):
    def add(self, ids: list[str], vectors: np.ndarray) -> None: ...
    def search(self, query_vector: np.ndarray, top_k: int) -> list[tuple[str, float]]: ...
    def save(self, path: Path) -> None: ...
    def load(self, path: Path) -> None: ...
    def __len__(self) -> int: ...


class NumpyVectorStore:
    """向量已 L2 归一化，余弦相似度退化为点积，一次矩阵乘法搞定。"""

    def __init__(self) -> None:
        self.ids: list[str] = []
        self.matrix: np.ndarray | None = None

    def add(self, ids: list[str], vectors: np.ndarray) -> None:
        vectors = np.asarray(vectors, dtype=np.float32)
        if self.matrix is None or self.matrix.size == 0:
            self.matrix = vectors
            self.ids = list(ids)
        else:
            self.matrix = np.vstack([self.matrix, vectors])
            self.ids.extend(ids)

    def search(self, query_vector: np.ndarray, top_k: int) -> list[tuple[str, float]]:
        if self.matrix is None or not len(self.ids):
            return []
        q = np.asarray(query_vector, dtype=np.float32)
        scores = self.matrix @ q
        k = min(top_k, len(self.ids))
        idx = np.argpartition(-scores, k - 1)[:k]
        idx = idx[np.argsort(-scores[idx])]
        return [(self.ids[i], float(scores[i])) for i in idx]

    def save(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if self.matrix is not None:
            np.save(path / "vectors.npy", self.matrix)
        (path / "ids.json").write_text(json.dumps(self.ids, ensure_ascii=False), encoding="utf-8")

    def load(self, path: Path) -> None:
        vec_file = path / "vectors.npy"
        id_file = path / "ids.json"
        if vec_file.exists():
            self.matrix = np.load(vec_file)
        if id_file.exists():
            self.ids = json.loads(id_file.read_text(encoding="utf-8"))

    def __len__(self) -> int:
        return len(self.ids)


class QdrantVectorStore:
    """Qdrant 后端（可选）。

    注意：qdrant-client 是同步的，放在 async 接口里会阻塞事件循环。
    这里为保持示例简洁没有包线程池，生产里请用 AsyncQdrantClient。
    """

    def __init__(self, collection: str, url: str = "http://127.0.0.1:6333", dim: int = 1024,
                 api_key: str = "", reset: bool = True) -> None:
        try:
            from qdrant_client import QdrantClient  # 延迟导入，没装也能跑 numpy 后端
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("请先 `pip install qdrant-client` 再使用 qdrant 后端") from exc

        self.collection = collection
        self.dim = dim
        self.client = QdrantClient(url=url, api_key=api_key or None)
        self._ensure_collection(reset)

    def _ensure_collection(self, reset: bool) -> None:
        from qdrant_client.models import Distance, VectorParams

        existing = {c.name for c in self.client.get_collections().collections}
        if self.collection in existing:
            if not reset:
                return
            self.client.delete_collection(self.collection)
        self.client.create_collection(
            collection_name=self.collection,
            vectors_config=VectorParams(size=self.dim, distance=Distance.COSINE),
        )

    def add(self, ids: list[str], vectors: np.ndarray) -> None:
        from qdrant_client.models import PointStruct

        points = [
            PointStruct(id=i, vector=v.tolist(), payload={"chunk_id": cid})
            for i, (cid, v) in enumerate(zip(ids, vectors))
        ]
        self.client.upsert(collection_name=self.collection, points=points)

    def search(self, query_vector: np.ndarray, top_k: int) -> list[tuple[str, float]]:
        hits = self.client.search(
            collection_name=self.collection, query_vector=query_vector.tolist(), limit=top_k
        )
        return [(h.payload["chunk_id"], float(h.score)) for h in hits]

    def save(self, path: Path) -> None:
        # 数据在 Qdrant 侧持久化，本地只留一份说明
        path.mkdir(parents=True, exist_ok=True)
        (path / "backend.txt").write_text(f"qdrant:{self.collection}", encoding="utf-8")

    def load(self, path: Path) -> None:
        return None

    def __len__(self) -> int:
        return int(self.client.count(self.collection).count)


def build_vector_store(
    backend: str, collection: str, dim: int, url: str, api_key: str, reset: bool = True
) -> VectorStore:
    if backend == "qdrant":
        return QdrantVectorStore(collection, url=url, dim=dim, api_key=api_key, reset=reset)
    return NumpyVectorStore()
