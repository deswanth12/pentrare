"""Hybrid Retriever module combining FTS5 lexical BM25 and dense semantic vector search."""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from rank_bm25 import BM25Okapi

from app.config import get_settings
from app.storage.database import DatabaseManager
from app.knowledge.vector_store import VectorStore
from app.knowledge.embeddings import EmbeddingGenerator


class SearchResult(BaseModel):
    """Normalized search result for a security methodology chunk."""
    chunk_id: str
    source_file: str
    source_path: str
    title: str
    section: str
    page: Optional[int] = None
    score: float
    content: str
    lexical_score: Optional[float] = None
    semantic_score: Optional[float] = None
    match_type: str = "both"  # "both", "lexical", "semantic"


def _tokenize(text: str) -> List[str]:
    """Tokenize query and content into lowercase words and alphanumeric tokens."""
    return re.findall(r"\b[a-zA-Z0-9_-]{2,}\b", text.lower())


class KnowledgeRetriever:
    """Retrieves relevant security knowledge chunks using FTS5, BM25, and dense vector embeddings."""

    def __init__(
        self,
        db: DatabaseManager,
        vector_store: Optional[VectorStore] = None,
        embedding_generator: Optional[EmbeddingGenerator] = None,
        lexical_weight: Optional[float] = None,
        semantic_weight: Optional[float] = None,
        auto_load_vectors: bool = True,
    ):
        self.db = db
        settings = get_settings()

        self.lexical_weight = (
            lexical_weight if lexical_weight is not None else settings.lexical_weight
        )
        self.semantic_weight = (
            semantic_weight if semantic_weight is not None else settings.semantic_weight
        )

        if vector_store is not None:
            self.vector_store = vector_store
            self.embedding_generator = embedding_generator
        elif auto_load_vectors and settings.app_env != "testing" and settings.vector_store_path.exists():
            vs = VectorStore(settings.vector_store_path)
            if vs.load() and vs.size() > 0:
                self.vector_store = vs
                self.embedding_generator = embedding_generator or EmbeddingGenerator(
                    model_name=settings.embedding_model
                )
            else:
                self.vector_store = None
                self.embedding_generator = None
        else:
            self.vector_store = None
            self.embedding_generator = None

    def search(
        self,
        query: str,
        limit: int = 5,
        mode: str = "hybrid",
    ) -> List[SearchResult]:
        """Search local knowledge base for relevant methodology chunks.

        Modes:
            - "hybrid": Fuses normalized BM25 lexical scores and dense vector cosine similarities.
            - "lexical": SQLite FTS5 search with BM25 Okapi re-ranking.
            - "semantic": Dense vector cosine similarity search via VectorStore.
        """
        clean_query = query.strip()
        if not clean_query:
            return []

        clean_mode = mode.lower().strip()
        if clean_mode == "lexical":
            return self._search_lexical(clean_query, limit)
        elif clean_mode == "semantic":
            return self._search_semantic(clean_query, limit)
        else:
            return self._search_hybrid(clean_query, limit)

    def _search_lexical(self, clean_query: str, limit: int) -> List[SearchResult]:
        """Execute pure lexical keyword and BM25 search."""
        candidate_limit = max(limit * 3, 20)
        candidates = self.db.search_chunks_fts(clean_query, limit=candidate_limit)

        if not candidates:
            return []

        corpus = [c["content"] for c in candidates]
        tokenized_corpus = [_tokenize(doc) for doc in corpus]
        tokenized_query = _tokenize(clean_query)

        if not tokenized_query or not any(tokenized_corpus):
            results = []
            for item in candidates[:limit]:
                raw_score = round(float(item.get("score", 1.0)), 4)
                results.append(
                    SearchResult(
                        chunk_id=item["chunk_id"],
                        source_file=item["source_file"],
                        source_path=item["source_path"],
                        title=item.get("title") or item["source_file"],
                        section=item.get("section") or "General",
                        page=item.get("page"),
                        score=raw_score,
                        content=item["content"],
                        lexical_score=raw_score,
                        semantic_score=None,
                        match_type="lexical",
                    )
                )
            return results

        bm25 = BM25Okapi(tokenized_corpus)
        doc_scores = bm25.get_scores(tokenized_query)

        scored_candidates = []
        for i, score in enumerate(doc_scores):
            scored_candidates.append((abs(float(score)), candidates[i]))

        scored_candidates.sort(key=lambda x: x[0], reverse=True)
        max_score = scored_candidates[0][0] if scored_candidates else 1.0

        results: List[SearchResult] = []
        for score, item in scored_candidates[:limit]:
            norm_score = round((score / max_score) if max_score > 0 else 1.0, 4)
            if norm_score == 0.0:
                norm_score = round(float(item.get("score", 1.0)), 4)

            results.append(
                SearchResult(
                    chunk_id=item["chunk_id"],
                    source_file=item["source_file"],
                    source_path=item["source_path"],
                    title=item.get("title") or item["source_file"],
                    section=item.get("section") or "General",
                    page=item.get("page"),
                    score=norm_score,
                    content=item["content"],
                    lexical_score=norm_score,
                    semantic_score=None,
                    match_type="lexical",
                )
            )

        return results

    def _search_semantic(self, clean_query: str, limit: int) -> List[SearchResult]:
        """Execute pure dense vector semantic similarity search."""
        if (
            self.vector_store is None
            or self.embedding_generator is None
            or self.vector_store.size() == 0
        ):
            raise RuntimeError(
                "Vector store is not initialized or contains no vectors. "
                "Run 'python app/main.py knowledge embeddings' to generate vector index."
            )

        query_emb = self.embedding_generator.embed_query(clean_query)
        vector_hits = self.vector_store.search(query_emb, top_k=limit)
        if not vector_hits:
            return []

        chunk_ids = [cid for cid, _ in vector_hits]
        hydrated = self.db.get_chunks_by_ids(chunk_ids)

        results: List[SearchResult] = []
        for cid, sim in vector_hits:
            if cid not in hydrated:
                continue
            item = hydrated[cid]
            norm_sim = round(max(0.0, min(1.0, float(sim))), 4)
            results.append(
                SearchResult(
                    chunk_id=cid,
                    source_file=item["source_file"],
                    source_path=item["source_path"],
                    title=item.get("title") or item["source_file"],
                    section=item.get("section") or "General",
                    page=item.get("page"),
                    score=norm_sim,
                    content=item["content"],
                    lexical_score=None,
                    semantic_score=norm_sim,
                    match_type="semantic",
                )
            )

        return results

    def _search_hybrid(self, clean_query: str, limit: int) -> List[SearchResult]:
        """Fuse lexical BM25 and dense semantic retrieval scores."""
        # Graceful fallback to lexical search if vector store is not available
        if (
            self.vector_store is None
            or self.embedding_generator is None
            or self.vector_store.size() == 0
        ):
            return self._search_lexical(clean_query, limit)

        candidate_limit = max(limit * 3, 20)

        # 1. Lexical retrieval candidates
        candidates = self.db.search_chunks_fts(clean_query, limit=candidate_limit)
        lexical_scores: Dict[str, float] = {}
        candidates_map: Dict[str, Dict[str, Any]] = {}

        if candidates:
            corpus = [c["content"] for c in candidates]
            tokenized_corpus = [_tokenize(doc) for doc in corpus]
            tokenized_query = _tokenize(clean_query)
            if tokenized_query and any(tokenized_corpus):
                bm25 = BM25Okapi(tokenized_corpus)
                raw_scores = bm25.get_scores(tokenized_query)
                max_bm25 = max(abs(float(s)) for s in raw_scores) if len(raw_scores) > 0 else 1.0
                for i, raw_s in enumerate(raw_scores):
                    cid = candidates[i]["chunk_id"]
                    candidates_map[cid] = candidates[i]
                    s = abs(float(raw_s))
                    norm_s = (s / max_bm25) if max_bm25 > 0 else 0.0
                    lexical_scores[cid] = norm_s
            else:
                for c in candidates:
                    cid = c["chunk_id"]
                    candidates_map[cid] = c
                    lexical_scores[cid] = 1.0

        # 2. Semantic retrieval candidates
        query_emb = self.embedding_generator.embed_query(clean_query)
        vector_hits = self.vector_store.search(query_emb, top_k=candidate_limit)
        semantic_scores: Dict[str, float] = {}
        for cid, sim in vector_hits:
            semantic_scores[cid] = max(0.0, min(1.0, float(sim)))

        # 3. Score Fusion
        all_cids = set(lexical_scores.keys()) | set(semantic_scores.keys())
        if not all_cids:
            return []

        fused_candidates = []
        for cid in all_cids:
            has_lex = cid in lexical_scores
            has_sem = cid in semantic_scores
            s_lex = lexical_scores.get(cid, 0.0)
            s_sem = semantic_scores.get(cid, 0.0)

            if has_lex and has_sem:
                match_type = "both"
            elif has_lex:
                match_type = "lexical"
            else:
                match_type = "semantic"

            final_score = (self.lexical_weight * s_lex) + (self.semantic_weight * s_sem)
            fused_candidates.append(
                (final_score, cid, s_lex if has_lex else None, s_sem if has_sem else None, match_type)
            )

        fused_candidates.sort(key=lambda x: x[0], reverse=True)
        top_candidates = fused_candidates[:limit]

        # Hydrate any missing chunk metadata (from semantic-only hits)
        missing_cids = [cid for _, cid, _, _, _ in top_candidates if cid not in candidates_map]
        if missing_cids:
            hydrated = self.db.get_chunks_by_ids(missing_cids)
            candidates_map.update(hydrated)

        results: List[SearchResult] = []
        for final_score, cid, s_lex, s_sem, match_type in top_candidates:
            if cid not in candidates_map:
                continue
            item = candidates_map[cid]
            results.append(
                SearchResult(
                    chunk_id=cid,
                    source_file=item["source_file"],
                    source_path=item["source_path"],
                    title=item.get("title") or item["source_file"],
                    section=item.get("section") or "General",
                    page=item.get("page"),
                    score=round(float(final_score), 4),
                    content=item["content"],
                    lexical_score=round(float(s_lex), 4) if s_lex is not None else None,
                    semantic_score=round(float(s_sem), 4) if s_sem is not None else None,
                    match_type=match_type,
                )
            )

        return results
