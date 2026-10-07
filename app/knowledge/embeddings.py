"""Dense vector embedding generator using local fastembed with CPU ONNX Runtime."""

import hashlib
from typing import List, Optional
import numpy as np


class EmbeddingGenerator:
    """Generates normalized dense vector embeddings for text chunks and queries."""

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        mock: bool = False,
        dimension: int = 384,
    ):
        self.model_name = model_name
        self.mock = mock
        self.dimension = dimension
        self._model = None

    def _get_model(self):
        """Lazy-load FastEmbed TextEmbedding model."""
        if self._model is None and not self.mock:
            from fastembed import TextEmbedding
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def embed_texts(self, texts: List[str], batch_size: int = 64) -> np.ndarray:
        """Generate unit-normalized embeddings for a list of text strings.

        Returns:
            np.ndarray of shape (len(texts), dimension) and dtype float32.
        """
        if not texts:
            return np.empty((0, self.dimension), dtype=np.float32)

        if self.mock:
            # Deterministic pseudo-embeddings for fast, offline testing
            rows = []
            for text in texts:
                seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
                rng = np.random.RandomState(seed)
                vec = rng.standard_normal(self.dimension).astype(np.float32)
                norm = float(np.linalg.norm(vec))
                if norm > 0:
                    vec = vec / norm
                rows.append(vec)
            return np.stack(rows).astype(np.float32)

        model = self._get_model()
        raw_embs = list(model.embed(texts, batch_size=batch_size))
        arr = np.array(raw_embs, dtype=np.float32)

        # Guarantee L2 unit normalization for cosine similarity
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        arr = np.where(norms > 0, arr / norms, arr)
        return arr.astype(np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """Generate unit-normalized embedding for a single search query string.

        Returns:
            np.ndarray of shape (dimension,) and dtype float32.
        """
        clean = query.strip()
        if not clean:
            return np.zeros(self.dimension, dtype=np.float32)

        vectors = self.embed_texts([clean])
        return vectors[0]
