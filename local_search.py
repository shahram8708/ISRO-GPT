"""DuckDuckGo-powered search utilities for the ISRO-GPT RAG pipeline."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

from duckduckgo_search import DDGS

from cache_utils import LRUCache


@dataclass
class SearchResult:
    """Normalized representation of a DuckDuckGo search hit."""

    title: str
    url: str
    snippet: str


class SearchError(Exception):
    """Raised when the search layer cannot complete a query."""


class LocalSearchClient:
    """Perform web searches without API keys using DuckDuckGo."""

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.max_results = max(int(config.get("SEARCH_MAX_RESULTS", 6)), 1)
        self.safe_search = (config.get("SEARCH_SAFE_MODE") or "moderate").lower()
        self.region = config.get("SEARCH_REGION") or "wt-wt"
        self.cache = LRUCache[str, List[SearchResult]](
            int(config.get("SEARCH_CACHE_SIZE", 32))
        )

    def search(self, query: str) -> List[SearchResult]:
        query = (query or "").strip()
        if not query:
            raise SearchError("Search query cannot be empty.")

        cache_key = query.lower()
        cached = self.cache.get(cache_key)
        if cached:
            self.logger.debug("DuckDuckGo cache hit for query '%s'", query)
            return cached

        results: List[SearchResult] = []
        seen_urls: set[str] = set()
        try:
            with DDGS() as ddgs:
                generator = ddgs.text(
                    query,
                    region=self.region,
                    safesearch=self.safe_search,
                    max_results=self.max_results,
                )
                for item in generator:
                    title = (item.get("title") or "").strip()
                    url = (item.get("href") or item.get("url") or "").strip()
                    body = (item.get("body") or item.get("snippet") or "").strip()
                    if url:
                        normalized = self._normalize_url(url)
                        if normalized in seen_urls:
                            continue
                        seen_urls.add(normalized)
                        results.append(SearchResult(title=title or url, url=normalized, snippet=body))
                        if len(results) >= self.max_results:
                            break
        except Exception as exc:  # noqa: BLE001 - upstream errors vary
            self.logger.error("DuckDuckGo search failed: %s", exc, exc_info=True)
            raise SearchError("DuckDuckGo search failed.") from exc

        if not results:
            raise SearchError("DuckDuckGo returned no search results.")
        self.cache.set(cache_key, results)
        return results

    @staticmethod
    def _normalize_url(url: str) -> str:
        try:
            parts = urlsplit(url)
        except ValueError:
            return url.strip()
        scheme = parts.scheme or "https"
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        return urlunsplit((scheme, netloc, path, parts.query, ""))
