"""End-to-end Retrieval Augmented Generation pipeline for ISRO-GPT."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup
from readability import Document

try:  # langdetect is optional but recommended for quality filtering.
    from langdetect import DetectorFactory, LangDetectException, detect

    DetectorFactory.seed = 0
except Exception:  # noqa: BLE001
    detect = None  # type: ignore
    LangDetectException = Exception  # type: ignore

from cache_utils import LRUCache
from llm_inference import LLMClient, LLMInferenceError
from local_search import LocalSearchClient, SearchError, SearchResult
from retriever import RetrievedDocument, RetrievalError, WhooshRetriever


@dataclass
class RAGResult:
    answer: str
    sources: List[Dict[str, str]]


class RAGPipelineError(Exception):
    """Raised when the RAG pipeline cannot return a valid answer."""


class RAGPipeline:
    """Glue code that wires searching, retrieval, and LLM inference together."""

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.search_client = LocalSearchClient(config, logger=self.logger)
        self.retriever = WhooshRetriever(
            chunk_token_target=int(config.get("RAG_CHUNK_TOKENS", 360)),
            overlap_tokens=int(config.get("RAG_CHUNK_OVERLAP_TOKENS", 40)),
            top_k=int(config.get("RAG_TOP_K", 5)),
            logger=self.logger,
        )
        self.llm_client = LLMClient(config, logger=self.logger)
        self.fetch_timeout = float(config.get("CONTENT_FETCH_TIMEOUT", 12))
        self.max_content_chars = int(config.get("RAG_MAX_CONTENT_CHARS", 9000))
        self.max_passages = int(config.get("RAG_MAX_CONTEXT_PASSAGES", 5))
        self.system_prompt = (
            config.get("LLM_SYSTEM_PROMPT")
            or "You are a ISRO-GPT AI assistant. Use only the provided web passages and their URLs to answer. "
            "If the answer is not contained in the passages, respond with 'I don't know.' Include citations in the form [n] that reference the provided URLs."
        )
        self.allowed_langs = {
            lang.strip().lower()
            for lang in str(config.get("SEARCH_ALLOWED_LANGS", "en")).split(",")
            if lang.strip()
        }

        user_agent = config.get("CONTENT_FETCH_USER_AGENT", "ISRO-GPT-RAG/1.0")
        self._http_headers = {"User-Agent": user_agent}

        cache_size = int(config.get("RAG_CONTENT_CACHE_SIZE", 32))
        answer_cache_size = int(config.get("RAG_ANSWER_CACHE_SIZE", 32))
        self._content_cache = LRUCache[str, List[RetrievedDocument]](cache_size)
        self._answer_cache = LRUCache[str, RAGResult](answer_cache_size)

    def run(self, question: str, *, history: Optional[str] = None) -> RAGResult:
        """Execute the RAG workflow for a user question."""
        cache_key = self._build_cache_key(question, history)
        cached_answer = self._answer_cache.get(cache_key)
        if cached_answer:
            self.logger.debug("RAG answer cache hit for query '%s'", question)
            return cached_answer

        pipeline_start = time.perf_counter()
        search_start = pipeline_start
        try:
            search_results = self.search_client.search(question)
        except SearchError as exc:
            self.logger.error("Web search failed: %s", exc, exc_info=True)
            raise RAGPipelineError("Unable to fetch search results. Please try again later.") from exc
        search_time = time.perf_counter() - search_start

        documents = self._collect_documents(question, search_results)
        if not documents:
            raise RAGPipelineError("Unable to fetch search results. Please try again later.")

        retrieval_start = time.perf_counter()
        try:
            self.retriever.index_documents(documents)
            top_docs = self.retriever.retrieve(question)
        except RetrievalError as exc:
            self.logger.error("Retrieval failed: %s", exc, exc_info=True)
            raise RAGPipelineError("Unable to process retrieved documents.") from exc
        retrieval_time = time.perf_counter() - retrieval_start

        if not top_docs:
            raise RAGPipelineError("No relevant documents were found for the query.")

        context_blocks, sources = self._build_context_blocks(top_docs)
        user_prompt = self._compose_prompt(question, history, context_blocks)

        generation_start = time.perf_counter()
        try:
            answer = self.llm_client.generate(self.system_prompt, user_prompt)
        except LLMInferenceError as exc:
            self.logger.error("LLM generation failed: %s", exc, exc_info=True)
            raise RAGPipelineError("Unable to generate a response at this time.") from exc
        generation_time = time.perf_counter() - generation_start

        result = RAGResult(answer=answer.strip(), sources=sources)
        total_time = time.perf_counter() - pipeline_start
        self.logger.info(
            "RAG pipeline timings | total: %.2fs | search: %.2fs | retrieval: %.2fs | generation: %.2fs",
            total_time,
            search_time,
            retrieval_time,
            generation_time,
        )

        self._answer_cache.set(cache_key, result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _collect_documents(
        self, query: str, search_results: List[SearchResult]
    ) -> List[RetrievedDocument]:
        cached = self._content_cache.get(query.lower())
        if cached:
            self.logger.debug("Document cache hit for query '%s'", query)
            return cached

        limited_results = search_results[: self.max_passages * 2]
        try:
            fetch_results = asyncio.run(self._fetch_documents_async(limited_results))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                fetch_results = loop.run_until_complete(
                    self._fetch_documents_async(limited_results)
                )
            finally:
                loop.close()

        documents: List[RetrievedDocument] = []
        seen_hashes: set[str] = set()
        for idx, (result, content) in enumerate(fetch_results, start=1):
            if not content:
                continue
            chunks = self.retriever.chunk_text(content)
            for chunk_idx, chunk in enumerate(chunks):
                chunk_hash = hash(chunk)
                if chunk_hash in seen_hashes:
                    continue
                seen_hashes.add(chunk_hash)
                doc_id = f"{idx}-{chunk_idx}"
                documents.append(
                    RetrievedDocument(
                        doc_id=doc_id,
                        title=result.title,
                        url=result.url,
                        content=chunk[: self.max_content_chars],
                    )
                )
                if len(documents) >= self.max_passages:
                    break
            if len(documents) >= self.max_passages:
                break

        self._content_cache.set(query.lower(), documents)
        return documents

    async def _fetch_documents_async(
        self, search_results: Iterable[SearchResult]
    ) -> List[Tuple[SearchResult, str]]:
        async with httpx.AsyncClient(headers=self._http_headers, timeout=self.fetch_timeout) as client:
            tasks = [self._fetch_single(client, result) for result in search_results]
            return await asyncio.gather(*tasks)

    async def _fetch_single(
        self, client: httpx.AsyncClient, result: SearchResult
    ) -> Tuple[SearchResult, str]:
        url = result.url
        if not url.startswith("http"):
            return result, result.snippet
        try:
            response = await client.get(url)
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Failed to fetch %s: %s", url, exc)
            return result, result.snippet

        text = self._extract_readable_text(response.text)
        if not text:
            text = result.snippet

        if self.allowed_langs and detect:
            try:
                language = detect(text[:4000])
                if language.lower() not in self.allowed_langs:
                    return result, ""
            except LangDetectException:
                pass

        return result, text[: self.max_content_chars]

    def _extract_readable_text(self, html: str) -> str:
        if not html:
            return ""
        try:
            doc = Document(html)
            summary_html = doc.summary(html_partial=True)
            soup = BeautifulSoup(summary_html, "html.parser")
        except Exception:  # noqa: BLE001
            soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "noscript", "header", "footer", "form"]):
            tag.decompose()

        text = " ".join(soup.stripped_strings)
        return text

    def _build_context_blocks(
        self, documents: List[RetrievedDocument]
    ) -> Tuple[List[str], List[Dict[str, str]]]:
        context_blocks: List[str] = []
        sources: List[Dict[str, str]] = []
        for idx, doc in enumerate(documents, start=1):
            context_blocks.append(f"[{idx}] {doc.content}\nSource: {doc.url}")
            sources.append({"title": doc.title or doc.url, "url": doc.url})
        return context_blocks, sources

    def _compose_prompt(self, question: str, history: Optional[str], context_blocks: List[str]) -> str:
        context_text = "\n\n".join(context_blocks)
        prompt_lines = [
            "Answer the user question using only the provided context passages.",
            "Cite sources inline using the [n] notation matching the context blocks.",
            "If the answer cannot be derived from the context, respond with 'I don't know.'",
        ]
        if history:
            prompt_lines.append("Conversation so far:\n" + history.strip())
        prompt_lines.append("User question: " + question.strip())
        prompt_lines.append("Context:\n" + context_text)
        return "\n\n".join(prompt_lines)

    @staticmethod
    def _build_cache_key(question: str, history: Optional[str]) -> str:
        history_key = history.strip() if history else ""
        return f"{question.strip().lower()}::{history_key.lower()}"
