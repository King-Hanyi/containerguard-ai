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

"""HybridSearcher: multi-signal retrieval fused with Reciprocal Rank Fusion.

This module combines three complementary retrieval signals:

* **FAISS semantic search** — dense vector similarity (embedding-based).
* **BM25 keyword search** — sparse lexical overlap (:class:`.BM25Searcher`).
* **Graph traversal** — structural CVE relationships (:class:`.GraphSearcher`).

The three ranked lists are merged using the **Reciprocal Rank Fusion (RRF)**
algorithm with a smoothing constant *k = 60*:

.. math::

    \\text{RRF}(d) = \\sum_{i} \\frac{1}{\\text{rank}_i(d) + 60}

where :math:`\\text{rank}_i(d)` is the 1-based position of document *d* in
retriever list *i*.  Documents absent from a list contribute 0 to the sum.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vuln_analysis.tools.bm25_search import BM25Searcher
    from vuln_analysis.tools.graph_search import GraphSearcher

logger = logging.getLogger(__name__)

# RRF smoothing constant — standard value from the 2009 paper by Cormack et al.
_RRF_K: int = 60


class HybridSearcher:
    """Multi-retriever search engine using Reciprocal Rank Fusion.

    Parameters
    ----------
    faiss_searcher:
        Any object that exposes ``search(query: str, top_k: int) -> list[dict]``
        where each dict contains at least a ``"doc"`` key.  In production this
        is typically a FAISS-backed dense retriever.
    bm25_searcher:
        A :class:`~vuln_analysis.tools.bm25_search.BM25Searcher` instance.
    graph_searcher:
        A :class:`~vuln_analysis.tools.graph_search.GraphSearcher` instance.

    Example
    -------
    >>> hybrid = HybridSearcher(faiss_searcher, bm25_searcher, graph_searcher)
    >>> results = hybrid.search("remote code execution via deserialization",
    ...                         cve_id="CVE-2021-44228", top_k=5)
    >>> results[0]["score"]   # combined RRF score
    0.03...
    """

    def __init__(
        self,
        faiss_searcher: Any,
        bm25_searcher: "BM25Searcher",
        graph_searcher: "GraphSearcher",
    ) -> None:
        self._faiss = faiss_searcher
        self._bm25 = bm25_searcher
        self._graph = graph_searcher
        logger.info("HybridSearcher initialised with three sub-retrievers.")

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def search(
        self,
        query: str,
        cve_id: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Run all three retrievers and return RRF-fused results.

        Parameters
        ----------
        query:
            Free-text search query forwarded to the FAISS and BM25 retrievers.
        cve_id:
            Optional seed CVE identifier forwarded to the graph searcher.
            When ``None``, the graph leg is skipped gracefully.
        top_k:
            Number of final results to return.

        Returns
        -------
        list[dict]
            Each element is::

                {
                    "doc":    str,    # Document text or CVE identifier
                    "score":  float,  # Aggregated RRF score (higher is better)
                    "source": str,    # Comma-separated list of contributing retrievers
                }

            Results are ordered by descending ``score``.
        """
        ranked_lists: list[tuple[str, list[dict[str, Any]]]] = []

        # ── 1. FAISS semantic search ──────────────────────────────────── #
        try:
            faiss_results = self._faiss.search(query, top_k=top_k * 2)
            ranked_lists.append(("faiss", faiss_results))
            logger.debug("FAISS returned %d results.", len(faiss_results))
        except Exception as exc:  # noqa: BLE001
            logger.warning("FAISS search failed, skipping: %s", exc)

        # ── 2. BM25 keyword search ────────────────────────────────────── #
        try:
            bm25_results = self._bm25.search(query, top_k=top_k * 2)
            ranked_lists.append(("bm25", bm25_results))
            logger.debug("BM25 returned %d results.", len(bm25_results))
        except Exception as exc:  # noqa: BLE001
            logger.warning("BM25 search failed, skipping: %s", exc)

        # ── 3. Graph traversal (optional) ─────────────────────────────── #
        if cve_id:
            try:
                graph_results = self._graph.search_related_vulns(cve_id)
                # Normalise graph results to the common {"doc": ...} schema
                normalised_graph = [
                    {"doc": r["cve_id"], **r} for r in graph_results
                ]
                ranked_lists.append(("graph", normalised_graph))
                logger.debug("Graph returned %d results.", len(graph_results))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graph search failed, skipping: %s", exc)

        if not ranked_lists:
            logger.warning("All retrievers failed or returned no results.")
            return []

        # ── 4. Reciprocal Rank Fusion ─────────────────────────────────── #
        rrf_scores: dict[str, float] = defaultdict(float)
        # Track which retrievers contributed to each document
        rrf_sources: dict[str, list[str]] = defaultdict(list)
        # Keep the first-seen raw dict for each document key
        rrf_docs: dict[str, dict[str, Any]] = {}

        for retriever_name, result_list in ranked_lists:
            for rank_zero, item in enumerate(result_list):
                doc_key: str = str(item.get("doc", ""))
                # 1-based rank → RRF contribution
                rrf_score = 1.0 / (rank_zero + 1 + _RRF_K)
                rrf_scores[doc_key] += rrf_score
                rrf_sources[doc_key].append(retriever_name)
                if doc_key not in rrf_docs:
                    rrf_docs[doc_key] = item

        # ── 5. Assemble and rank final results ─────────────────────────── #
        fused: list[dict[str, Any]] = []
        for doc_key, agg_score in sorted(
            rrf_scores.items(), key=lambda kv: kv[1], reverse=True
        ):
            entry = dict(rrf_docs[doc_key])  # shallow copy of original dict
            entry["score"] = round(agg_score, 6)
            entry["source"] = ", ".join(rrf_sources[doc_key])
            fused.append(entry)

        final = fused[:top_k]
        logger.info(
            "HybridSearcher.search('%s', cve_id=%s, top_k=%d) → %d results "
            "(top RRF score=%.6f).",
            query,
            cve_id,
            top_k,
            len(final),
            final[0]["score"] if final else 0.0,
        )
        return final
