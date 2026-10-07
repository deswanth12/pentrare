"""NumPy-based vector store for local dense embedding storage and cosine similarity search."""

from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import numpy as np


class VectorStore:
    """Manages local dense vector embeddings saved in compressed NumPy (.npz) format."""

    def __init__(self, file_path: Path | str, dimension: int = 384):
        self.file_path = Path(file_path)
        self.dimension = dimension
        self.chunk_ids: List[str] = []
        self.embeddings: Optional[np.ndarray] = None
        self.content_hashes: Dict[str, str] = {}
        self._id_to_index: Dict[str, int] = {}

    def load(self) -> bool:
        """Load vector store from disk if file exists. Returns True if loaded, False otherwise."""
        if not self.file_path.exists():
            self.clear()
            return False

        try:
            with np.load(self.file_path, allow_pickle=True) as data:
                raw_ids = data["chunk_ids"]
                self.chunk_ids = [str(cid) for cid in raw_ids]
                self.embeddings = data["embeddings"].astype(np.float32)

                if "content_hashes" in data:
                    raw_hashes = data["content_hashes"]
                    self.content_hashes = {
                        str(self.chunk_ids[i]): str(raw_hashes[i])
                        for i in range(len(self.chunk_ids))
                    }
                else:
                    self.content_hashes = {}

            self._id_to_index = {cid: idx for idx, cid in enumerate(self.chunk_ids)}
            return True
        except Exception:
            self.clear()
            return False

    def save(self) -> None:
        """Save vector store to disk as compressed .npz archive."""
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if self.embeddings is None or len(self.chunk_ids) == 0:
            chunk_ids_arr = np.array([], dtype=object)
            embs_arr = np.empty((0, self.dimension), dtype=np.float32)
            hashes_arr = np.array([], dtype=object)
        else:
            chunk_ids_arr = np.array(self.chunk_ids, dtype=object)
            embs_arr = self.embeddings.astype(np.float32)
            hashes_arr = np.array(
                [self.content_hashes.get(cid, "") for cid in self.chunk_ids],
                dtype=object,
            )

        np.savez_compressed(
            self.file_path,
            chunk_ids=chunk_ids_arr,
            embeddings=embs_arr,
            content_hashes=hashes_arr,
        )

    def add_chunks(
        self,
        chunk_ids: List[str],
        embeddings: np.ndarray,
        content_hashes: Optional[List[str]] = None,
    ) -> int:
        """Add or update chunk vectors in the index.

        Args:
            chunk_ids: List of unique chunk IDs.
            embeddings: Float32 matrix of shape (len(chunk_ids), dimension).
            content_hashes: Optional list of chunk content hashes for incremental updates.

        Returns:
            Number of chunks added or updated.
        """
        if not chunk_ids:
            return 0

        embeddings = np.asarray(embeddings, dtype=np.float32)
        if embeddings.ndim == 1:
            embeddings = embeddings.reshape(1, -1)

        if len(chunk_ids) != embeddings.shape[0]:
            raise ValueError(
                f"Mismatch: {len(chunk_ids)} chunk IDs but {embeddings.shape[0]} embeddings."
            )

        if embeddings.shape[1] != self.dimension:
            raise ValueError(
                f"Expected embedding dimension {self.dimension}, got {embeddings.shape[1]}."
            )

        if content_hashes is None:
            content_hashes = ["" for _ in chunk_ids]

        new_ids = []
        new_embs = []
        updated_count = 0

        for i, cid in enumerate(chunk_ids):
            chash = content_hashes[i]
            if cid in self._id_to_index:
                idx = self._id_to_index[cid]
                if self.embeddings is not None:
                    self.embeddings[idx] = embeddings[i]
                self.content_hashes[cid] = chash
                updated_count += 1
            else:
                new_ids.append(cid)
                new_embs.append(embeddings[i])
                self.content_hashes[cid] = chash

        if new_ids:
            new_embs_mat = np.array(new_embs, dtype=np.float32)
            if self.embeddings is None or len(self.chunk_ids) == 0:
                self.chunk_ids = list(new_ids)
                self.embeddings = new_embs_mat
            else:
                self.chunk_ids.extend(new_ids)
                self.embeddings = np.vstack([self.embeddings, new_embs_mat])

            self._id_to_index = {cid: idx for idx, cid in enumerate(self.chunk_ids)}

        return updated_count + len(new_ids)

    def delete_chunks(self, chunk_ids: List[str]) -> int:
        """Delete specified chunk IDs from index."""
        if not chunk_ids or not self.chunk_ids or self.embeddings is None:
            return 0

        ids_to_remove = set(chunk_ids)
        keep_indices = [
            i for i, cid in enumerate(self.chunk_ids) if cid not in ids_to_remove
        ]

        deleted_count = len(self.chunk_ids) - len(keep_indices)
        if deleted_count == 0:
            return 0

        self.chunk_ids = [self.chunk_ids[i] for i in keep_indices]
        self.embeddings = self.embeddings[keep_indices]
        for cid in ids_to_remove:
            self.content_hashes.pop(cid, None)

        self._id_to_index = {cid: idx for idx, cid in enumerate(self.chunk_ids)}
        return deleted_count

    def search(self, query_embedding: np.ndarray, top_k: int = 5) -> List[Tuple[str, float]]:
        """Search vector store by cosine similarity.

        Returns:
            List of (chunk_id, similarity_score) tuples sorted descending by score.
        """
        if self.embeddings is None or len(self.chunk_ids) == 0:
            return []

        query_vec = np.asarray(query_embedding, dtype=np.float32)
        if query_vec.ndim > 1:
            query_vec = query_vec.flatten()

        # Dot product gives cosine similarity since vectors are unit-normalized
        scores = np.dot(self.embeddings, query_vec)

        total = len(self.chunk_ids)
        k = min(top_k, total)
        if k <= 0:
            return []

        if k == total:
            indices = np.argsort(-scores)
        else:
            top_part = np.argpartition(-scores, k)[:k]
            indices = top_part[np.argsort(-scores[top_part])]

        return [(self.chunk_ids[idx], float(scores[idx])) for idx in indices[:k]]

    def contains(self, chunk_id: str) -> bool:
        """Check if chunk ID exists in vector store."""
        return chunk_id in self._id_to_index

    def get_content_hash(self, chunk_id: str) -> Optional[str]:
        """Get stored content hash for a chunk ID."""
        return self.content_hashes.get(chunk_id)

    def size(self) -> int:
        """Return number of vectors in index."""
        return len(self.chunk_ids)

    def clear(self) -> None:
        """Reset index in memory."""
        self.chunk_ids = []
        self.embeddings = None
        self.content_hashes = {}
        self._id_to_index = {}
