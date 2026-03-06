# Copyright 2024 ContainerGuard AI Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""BM25Searcher: keyword-based retrieval using the BM25Okapi algorithm.

This module provides a lightweight wrapper around :class:`rank_bm25.BM25Okapi`
that accepts a plain-text corpus and exposes a simple ``search`` interface
consistent with the other searchers in the hybrid retrieval pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from rank_bm25 import BM25Okapi

logger = logging.getLogger(__name__)


class BM25Searcher:
    """Keyword retriever backed by BM25Okapi.

    Parameters
    ----------
    corpus:
        List of raw text documents that form the search index.  Each entry
        is stored verbatim and returned in search results so callers can
        map scores back to the original text.

    Example
    -------
    >>> searcher = BM25Searcher(["buffer overflow in libc", "SQL injection"])
    >>> results = searcher.search("memory overflow", top_k=1)
    >>> results[0]["doc"]
    'buffer overflow in libc'
    """

    def __init__(self, corpus: list[str]) -> None:
        if not corpus:
            raise ValueError("corpus must contain at least one document.")

        self._corpus: list[str] = corpus
        # BM25Okapi expects a pre-tokenised corpus (list of token lists).
        tokenised = [doc.lower().split() for doc in corpus]
        self._bm25 = BM25Okapi(tokenised)
        logger.info("BM25Searcher initialised with %d documents.", len(corpus))

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Return the *top_k* documents most relevant to *query*.

        Parameters
        ----------
        query:
            Free-text query string.  Tokenisation mirrors the indexing step
            (lowercase, whitespace split).
        top_k:
            Maximum number of results to return.  If the corpus is smaller
            than *top_k*, all documents are returned.

        Returns
        -------
        list[dict]
            Each element is ``{"doc": str, "score": float}``, ordered by
            descending BM25 score.  Documents with a score of 0 are still
            included so downstream RRF fusion can assign them a rank.
        """
        if not query or not query.strip():
            logger.warning("BM25Searcher.search called with an empty query.")
            return []

        tokens = query.lower().split()
        scores: list[float] = self._bm25.get_scores(tokens).tolist()

        # Pair each document with its score and sort descending.
        ranked = sorted(
            zip(self._corpus, scores),
            key=lambda pair: pair[1],
            reverse=True,
        )

        results = [
            {"doc": doc, "score": score}
            for doc, score in ranked[:top_k]
        ]

        logger.debug(
            "BM25 search('%s', top_k=%d) → %d results (top score=%.4f)",
            query,
            top_k,
            len(results),
            results[0]["score"] if results else 0.0,
        )
        return results
