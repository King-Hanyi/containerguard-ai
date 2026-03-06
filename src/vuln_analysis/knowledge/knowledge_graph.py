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

"""KnowledgeGraph: in-memory query layer over BRON-loaded CVE mappings."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """In-memory graph built from BRON CVE mapping data.

    Parameters
    ----------
    cve_data:
        Dictionary produced by :class:`~bron_loader.BRONLoader`, with the
        canonical schema::

            {
                "CVE-ID": {
                    "cwes": ["CWE-79", ...],
                    "capecs": ["CAPEC-86", ...],
                    "attack_techniques": ["T1059", ...],
                }
            }

    Example
    -------
    >>> from bron_loader import BRONLoader
    >>> from knowledge_graph import KnowledgeGraph
    >>> data = BRONLoader().load("/path/to/BRON")
    >>> kg = KnowledgeGraph(data)
    >>> chain = kg.query_attack_chain("CVE-2021-44228")
    >>> related = kg.get_related_cves("CWE-502")
    """

    def __init__(self, cve_data: dict[str, dict[str, list[str]]]) -> None:
        self._cve_data: dict[str, dict[str, list[str]]] = cve_data

        # Reverse index: CWE → list[CVE-ID]
        self._cwe_index: dict[str, list[str]] = defaultdict(list)
        # Reverse index: CAPEC → list[CVE-ID]
        self._capec_index: dict[str, list[str]] = defaultdict(list)
        # Reverse index: ATT&CK technique → list[CVE-ID]
        self._technique_index: dict[str, list[str]] = defaultdict(list)

        self._build_indices()
        logger.info(
            "KnowledgeGraph initialised: %d CVEs, %d CWEs, %d CAPECs, "
            "%d ATT&CK techniques",
            len(self._cve_data),
            len(self._cwe_index),
            len(self._capec_index),
            len(self._technique_index),
        )

    # ------------------------------------------------------------------ #
    # Public query API                                                      #
    # ------------------------------------------------------------------ #

    def query_attack_chain(self, cve_id: str) -> dict[str, Any]:
        """Return the full attack chain for a given CVE.

        The returned dictionary follows the same schema as the source data
        but enriched with a human-readable ``summary`` field:

        .. code-block:: python

            {
                "cve_id": "CVE-2023-36632",
                "cwes": ["CWE-20"],
                "capecs": ["CAPEC-153"],
                "attack_techniques": ["T1059"],
                "summary": "...",
                "found": True,
            }

        Parameters
        ----------
        cve_id:
            The CVE identifier to look up (case-insensitive).

        Returns
        -------
        dict
            Attack chain dictionary; ``found`` is ``False`` when the CVE is
            not present in the loaded dataset.
        """
        normalised = cve_id.strip().upper()
        entry = self._cve_data.get(normalised)

        if entry is None:
            logger.warning("CVE not found in BRON dataset: %s", normalised)
            return {
                "cve_id": normalised,
                "cwes": [],
                "capecs": [],
                "attack_techniques": [],
                "summary": (
                    f"{normalised} was not found in the current BRON dataset. "
                    "Ensure the dataset is up to date or the CVE ID is correct."
                ),
                "found": False,
            }

        cwes = entry.get("cwes", [])
        capecs = entry.get("capecs", [])
        techniques = entry.get("attack_techniques", [])

        summary_parts = [f"CVE: {normalised}"]
        if cwes:
            summary_parts.append(f"Weakness types: {', '.join(cwes)}")
        if capecs:
            summary_parts.append(f"Attack patterns: {', '.join(capecs)}")
        if techniques:
            summary_parts.append(f"ATT&CK techniques: {', '.join(techniques)}")

        return {
            "cve_id": normalised,
            "cwes": cwes,
            "capecs": capecs,
            "attack_techniques": techniques,
            "summary": " | ".join(summary_parts),
            "found": True,
        }

    def get_related_cves(self, cwe_id: str) -> list[str]:
        """Return all CVEs associated with a given CWE identifier.

        Parameters
        ----------
        cwe_id:
            The CWE identifier (e.g. ``'CWE-79'``).  Leading/trailing
            whitespace and case differences are handled automatically.

        Returns
        -------
        list[str]
            Sorted list of CVE identifiers linked to *cwe_id*.  Returns an
            empty list when the CWE is not present in the dataset.
        """
        normalised = self._normalise_cwe(cwe_id)
        cves = self._cwe_index.get(normalised, [])
        logger.debug(
            "get_related_cves(%s) → %d CVEs", normalised, len(cves)
        )
        return sorted(cves)

    def get_related_cves_by_capec(self, capec_id: str) -> list[str]:
        """Return all CVEs linked to a CAPEC attack pattern.

        Parameters
        ----------
        capec_id:
            The CAPEC identifier (e.g. ``'CAPEC-86'``).

        Returns
        -------
        list[str]
            Sorted list of CVE identifiers.
        """
        key = capec_id.strip().upper()
        return sorted(self._capec_index.get(key, []))

    def get_related_cves_by_technique(self, technique_id: str) -> list[str]:
        """Return all CVEs linked to a MITRE ATT&CK technique.

        Parameters
        ----------
        technique_id:
            ATT&CK technique ID (e.g. ``'T1059'``).

        Returns
        -------
        list[str]
            Sorted list of CVE identifiers.
        """
        key = technique_id.strip().upper()
        return sorted(self._technique_index.get(key, []))

    def all_cves(self) -> list[str]:
        """Return a sorted list of all CVE IDs in the graph."""
        return sorted(self._cve_data.keys())

    def stats(self) -> dict[str, int]:
        """Return dataset statistics."""
        return {
            "cve_count": len(self._cve_data),
            "cwe_count": len(self._cwe_index),
            "capec_count": len(self._capec_index),
            "technique_count": len(self._technique_index),
        }

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    def _build_indices(self) -> None:
        """Populate reverse-lookup indices from *_cve_data*."""
        for cve_id, entry in self._cve_data.items():
            for cwe in entry.get("cwes", []):
                self._cwe_index[cwe].append(cve_id)
            for capec in entry.get("capecs", []):
                self._capec_index[capec].append(cve_id)
            for technique in entry.get("attack_techniques", []):
                self._technique_index[technique].append(cve_id)

    @staticmethod
    def _normalise_cwe(cwe_id: str) -> str:
        """Return ``'CWE-<number>'`` form regardless of input format."""
        import re

        upper = cwe_id.strip().upper()
        match = re.search(r"\d+", upper)
        return f"CWE-{match.group(0)}" if match else upper
