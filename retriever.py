"""Document retrieval utilities for the ISRO-GPT RAG pipeline."""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Iterable, List, Optional

from whoosh.analysis import StemmingAnalyzer
from whoosh.fields import ID, TEXT, Schema
from whoosh.filedb.filestore import RamStorage
from whoosh.qparser import MultifieldParser


@dataclass
class RetrievedDocument:
    """Structure holding a chunked document and its metadata."""

    doc_id: str
    title: str
    url: str
    content: str
    score: float = 0.0


class RetrievalError(Exception):
    """Raised when the retrieval layer encounters an unrecoverable issue."""


class WhooshRetriever:
    """In-memory BM25-style retriever powered by Whoosh."""

    def __init__(
        self,
        *,
        chunk_token_target: int = 360,
        overlap_tokens: int = 40,
        top_k: int = 5,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        if chunk_token_target <= 0:
            raise ValueError("chunk_token_target must be positive")
        if overlap_tokens < 0:
            raise ValueError("overlap_tokens cannot be negative")
        if overlap_tokens >= chunk_token_target:
            raise ValueError("overlap_tokens must be smaller than chunk_token_target")

        self.chunk_token_target = chunk_token_target
        self.overlap_tokens = overlap_tokens
        self.top_k = top_k
        self.logger = logger or logging.getLogger(__name__)

        schema = Schema(
            doc_id=ID(stored=True, unique=True),
            title=TEXT(stored=True, analyzer=StemmingAnalyzer()),
            url=ID(stored=True),
            content=TEXT(stored=True, analyzer=StemmingAnalyzer()),
        )
        storage = RamStorage()
        self._index = storage.create_index(schema)
        self._parser = MultifieldParser(["title", "content"], schema=schema)

    def reset(self) -> None:
        """Clear all indexed documents."""
        storage = RamStorage()
        schema = self._index.schema
        self._index = storage.create_index(schema)
        self._parser = MultifieldParser(["title", "content"], schema=schema)

    def chunk_text(self, text: str) -> List[str]:
        """Chunk text into overlapping windows for more granular retrieval."""
        clean = (text or "").strip()
        if not clean:
            return []

        tokens = clean.split()
        if not tokens:
            return []

        max_tokens_per_chunk = max(self.chunk_token_target, 1)
        overlap_tokens = min(self.overlap_tokens, max_tokens_per_chunk - 1)

        chunks: List[str] = []
        start = 0
        while start < len(tokens):
            end = min(start + max_tokens_per_chunk, len(tokens))
            chunk = " ".join(tokens[start:end]).strip()
            if chunk:
                chunks.append(chunk)
            if end == len(tokens):
                break
            start = max(end - overlap_tokens, start + 1)
        return chunks

    def index_documents(self, documents: Iterable[RetrievedDocument]) -> None:
        """Index a batch of documents. Existing index contents are replaced."""
        storage = RamStorage()
        schema = self._index.schema
        self._index = storage.create_index(schema)
        writer = self._index.writer()
        count = 0
        for doc in documents:
            writer.update_document(
                doc_id=doc.doc_id,
                title=doc.title,
                url=doc.url,
                content=doc.content,
            )
            count += 1
        writer.commit()
        self.logger.debug("Indexed %s document chunks for retrieval.", count)

    def retrieve(self, query: str) -> List[RetrievedDocument]:
        """Retrieve the top-k documents for a query using BM25 scoring."""
        query = (query or "").strip()
        if not query:
            raise RetrievalError("Query cannot be empty for retrieval.")

        parsed = self._parser.parse(query)
        with self._index.searcher() as searcher:
            results = searcher.search(parsed, limit=self.top_k)
            retrieved: List[RetrievedDocument] = []
            for hit in results:
                retrieved.append(
                    RetrievedDocument(
                        doc_id=hit["doc_id"],
                        title=hit.get("title", hit.get("url", "")),
                        url=hit.get("url", ""),
                        content=hit.get("content", ""),
                        score=float(hit.score),
                    )
                )
        return retrieved
