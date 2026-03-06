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

"""GraphSearcher: structure-aware CVE retrieval via the BRON KnowledgeGraph.

Given a seed CVE identifier, this searcher traverses the in-memory knowledge
graph to find structurally similar vulnerabilities that share the same CWE
weakness types, CAPEC attack patterns, or MITRE ATT&CK techniques.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vuln_analysis.knowledge.knowledge_graph import KnowledgeGraph

logger = logging.getLogger(__name__)


class GraphSearcher:
    """Knowledge-graph-based vulnerability retriever.

    Parameters
    ----------
    kg:
        A fully initialised :class:`~vuln_analysis.knowledge.knowledge_graph.KnowledgeGraph`
        instance loaded from the BRON dataset (or any compatible graph object
        that exposes the same query API).

    Example
    -------
    >>> from vuln_analysis.knowledge.bron_loader import BRONLoader
    >>> from vuln_analysis.knowledge.knowledge_graph import KnowledgeGraph
    >>> data = BRONLoader().load("/path/to/BRON")
    >>> kg = KnowledgeGraph(data)
    >>> searcher = GraphSearcher(kg)
    >>> results = searcher.search_related_vulns("CVE-2021-44228")
    """

    def __init__(self, kg: "KnowledgeGraph") -> None:
        self._kg = kg
        logger.info("GraphSearcher initialised (graph stats: %s).", kg.stats())

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def search_related_vulns(self, cve_id: str) -> list[dict[str, str]]:
        """Return CVEs structurally related to *cve_id* via shared CWEs.

        The method performs a two-hop lookup:

        1. Retrieve the attack chain for *cve_id* to obtain its CWE tags.
        2. For each CWE, retrieve all sibling CVEs that share that weakness.
        3. Deduplicate, exclude the seed CVE itself, and annotate each result
           with the relation type (``"shared_cwe"``) and the bridging CWE.

        Parameters
        ----------
        cve_id:
            The seed CVE identifier (e.g. ``'CVE-2023-36632'``).

        Returns
        -------
        list[dict]
            Each element is::

                {
                    "cve_id":    str,   # Related CVE identifier
                    "relation":  str,   # Relation type, e.g. "shared_cwe"
                    "via":       str,   # The shared node (e.g. "CWE-20")
                    "source_cve": str,  # The seed CVE
                }

            Returns an empty list if *cve_id* is not present in the graph or
            has no CWE annotations (and therefore no reachable neighbours).
        """
        normalised = cve_id.strip().upper()
        chain = self._kg.query_attack_chain(normalised)

        if not chain.get("found"):
            logger.warning(
                "GraphSearcher: %s not found in knowledge graph.", normalised
            )
            return []

        cwes: list[str] = chain.get("cwes", [])
        if not cwes:
            logger.debug(
                "GraphSearcher: %s has no CWE annotations; no related CVEs.",
                normalised,
            )
            return []

        # Two-hop: seed CVE → CWE → sibling CVEs
        seen: set[str] = {normalised}
        results: list[dict[str, str]] = []

        for cwe in cwes:
            siblings = self._kg.get_related_cves(cwe)
            for sibling in siblings:
                if sibling in seen:
                    continue
                seen.add(sibling)
                results.append(
                    {
                        "cve_id": sibling,
                        "relation": "shared_cwe",
                        "via": cwe,
                        "source_cve": normalised,
                    }
                )

        logger.debug(
            "GraphSearcher.search_related_vulns('%s') → %d related CVEs "
            "via %d CWEs.",
            normalised,
            len(results),
            len(cwes),
        )
        return results
