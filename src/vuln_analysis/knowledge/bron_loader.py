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

"""BRON data loader for parsing CVE → CWE → CAPEC → ATT&CK mappings."""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BRONLoader:
    """Loads and parses the BRON knowledge graph dataset.

    BRON (Bidirectional Reachability of Offensive kNowledge) provides
    structured mappings between CVEs, CWEs, CAPECs, and MITRE ATT&CK
    techniques. This loader reads the BRON JSON/JSONL files and returns
    a normalised dictionary keyed by CVE ID.

    Example
    -------
    >>> loader = BRONLoader()
    >>> data = loader.load("/path/to/BRON")
    >>> print(data["CVE-2021-44228"])
    {"cwes": ["CWE-502"], "capecs": ["CAPEC-242"], "attack_techniques": ["T1190"]}
    """

    # ------------------------------------------------------------------ #
    # BRON dataset paths (relative to the repo root)                       #
    # ------------------------------------------------------------------ #
    _CVE_FILE = "BRON/graph_data/cve.json"
    _CWE_FILE = "BRON/graph_data/cwe.json"
    _CAPEC_FILE = "BRON/graph_data/capec.json"
    _TECHNIQUE_FILE = "BRON/graph_data/technique.json"
    _EDGE_FILE = "BRON/graph_data/all_edges.json"

    # Alternative flat-file layout used in some BRON releases
    _JSONL_DIR = "BRON/original_attck_json"

    def load(self, bron_data_dir: str) -> dict[str, dict[str, list[str]]]:
        """Parse the BRON dataset and return a CVE-keyed mapping.

        Parameters
        ----------
        bron_data_dir:
            Absolute (or relative) path to the cloned BRON repository.

        Returns
        -------
        dict
            ``{"CVE-ID": {"cwes": [...], "capecs": [...], "attack_techniques": [...]}}``
        """
        bron_path = Path(bron_data_dir)
        if not bron_path.exists():
            raise FileNotFoundError(
                f"BRON directory not found: {bron_data_dir}"
            )

        logger.info("Loading BRON dataset from: %s", bron_path.resolve())

        # Try different known layouts in order of preference
        result = (
            self._load_cve_map(bron_path)
            or self._load_graph_data(bron_path)
            or self._load_jsonl_data(bron_path)
            or self._load_raw_json(bron_path)
        )

        logger.info("Loaded %d CVE entries from BRON.", len(result))
        return result

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    def _load_cve_map(
        self, bron_path: Path
    ) -> dict[str, dict[str, list[str]]] | None:
        """Load from BRON-generated cve_map_cpe_cwe_score[_last_five_years].json.

        These files are produced by
        ``download_threat_information/parsing_scripts/parse_cve.py``
        and have the schema::

            {
                "CVE-YYYY-NNNNN": {
                    "cwes": ["79", "20", ...],   # plain CWE numbers!
                    "cpes": [...],
                    "score": 7.5,
                    ...
                }
            }
        """
        candidates = [
            bron_path / "cve_map_cpe_cwe_score.json",
            bron_path / "cve_map_cpe_cwe_score_last_five_years.json",
            bron_path / "data" / "cve_map_cpe_cwe_score.json",
        ]
        # also scan one level deep for these file names
        for sub in bron_path.iterdir():
            if sub.is_dir():
                candidates.append(sub / "cve_map_cpe_cwe_score.json")
                candidates.append(
                    sub / "cve_map_cpe_cwe_score_last_five_years.json"
                )

        for candidate in candidates:
            if not candidate.exists():
                continue
            logger.debug("Using cve_map layout: %s", candidate)
            try:
                with candidate.open(encoding="utf-8") as fh:
                    raw: dict[str, Any] = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read %s: %s", candidate, exc)
                continue

            result: dict[str, dict[str, list[str]]] = {}
            for cve_id, entry in raw.items():
                cve_norm = self._extract_cve(cve_id) or cve_id.upper()
                cwes = [
                    f"CWE-{num}" if not str(num).upper().startswith("CWE")
                    else str(num).upper()
                    for num in entry.get("cwes", [])
                ]
                result[cve_norm] = {
                    "cwes": cwes,
                    # cve_map does not contain CAPEC/technique links directly;
                    # those require the full ArangoDB graph export.
                    "capecs": [],
                    "attack_techniques": [],
                }
            logger.info(
                "cve_map loader: loaded %d CVEs from %s", len(result), candidate
            )
            return result

        return None

    def _load_graph_data(
        self, bron_path: Path
    ) -> dict[str, dict[str, list[str]]] | None:
        """Load from BRON/graph_data/ layout (structured JSON files)."""
        edge_path = bron_path / "graph_data" / "all_edges.json"
        if not edge_path.exists():
            # Try one level up (user may have passed the repo root directly)
            edge_path = bron_path / "BRON" / "graph_data" / "all_edges.json"
        if not edge_path.exists():
            return None

        logger.debug("Using graph_data layout: %s", edge_path)
        try:
            with edge_path.open(encoding="utf-8") as fh:
                edges: list[dict[str, Any]] = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read edge file %s: %s", edge_path, exc)
            return None

        return self._edges_to_cve_map(edges)

    def _load_jsonl_data(
        self, bron_path: Path
    ) -> dict[str, dict[str, list[str]]] | None:
        """Load from BRON JSONL files (line-delimited JSON)."""
        candidates = list(bron_path.rglob("*.jsonl"))
        if not candidates:
            return None

        result: dict[str, dict[str, list[str]]] = {}
        for jsonl_file in candidates:
            if "cve" not in jsonl_file.name.lower():
                continue
            logger.debug("Reading JSONL: %s", jsonl_file)
            try:
                with jsonl_file.open(encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        record = json.loads(line)
                        self._merge_record(record, result)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping %s: %s", jsonl_file, exc)
        return result if result else None

    def _load_raw_json(
        self, bron_path: Path
    ) -> dict[str, dict[str, list[str]]]:
        """Fallback: walk all JSON files and extract CVE-related records."""
        result: dict[str, dict[str, list[str]]] = {}
        json_files = list(bron_path.rglob("*.json"))
        logger.debug("Fallback: scanning %d JSON files", len(json_files))
        for json_file in json_files:
            try:
                with json_file.open(encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        self._merge_record(item, result)
            elif isinstance(data, dict):
                self._merge_record(data, result)

        return result

    # ------------------------------------------------------------------ #
    # Record-level parsing utilities                                        #
    # ------------------------------------------------------------------ #

    def _edges_to_cve_map(
        self, edges: list[dict[str, Any]]
    ) -> dict[str, dict[str, list[str]]]:
        """Convert a flat list of BRON edges into a CVE-keyed dictionary."""
        result: dict[str, dict[str, list[str]]] = {}

        for edge in edges:
            src: str = str(edge.get("_from", edge.get("from", "")))
            dst: str = str(edge.get("_to", edge.get("to", "")))
            rel: str = str(edge.get("_type", edge.get("type", ""))).lower()

            cve_id = self._extract_cve(src) or self._extract_cve(dst)
            if not cve_id:
                continue

            entry = result.setdefault(
                cve_id, {"cwes": [], "capecs": [], "attack_techniques": []}
            )

            other = dst if self._extract_cve(src) else src
            if "cwe" in rel or other.upper().startswith("CWE"):
                _append_unique(entry["cwes"], self._normalise_id(other, "CWE-"))
            elif "capec" in rel or other.upper().startswith("CAPEC"):
                _append_unique(
                    entry["capecs"], self._normalise_id(other, "CAPEC-")
                )
            elif "technique" in rel or "attack" in rel or other.upper().startswith("T"):
                _append_unique(
                    entry["attack_techniques"],
                    self._normalise_technique(other),
                )

        return result

    def _merge_record(
        self,
        record: dict[str, Any],
        result: dict[str, dict[str, list[str]]],
    ) -> None:
        """Merge a single JSON record into *result* if it contains a CVE."""
        # Detect CVE ID from common field names
        cve_id: str | None = None
        for key in ("cve_id", "CVE_ID", "id", "cve", "name"):
            val = record.get(key, "")
            cve_id = self._extract_cve(str(val))
            if cve_id:
                break
        if not cve_id:
            return

        entry = result.setdefault(
            cve_id, {"cwes": [], "capecs": [], "attack_techniques": []}
        )

        # CWEs
        for raw in self._iter_field(record, ("cwe", "cwes", "CWE")):
            norm = self._normalise_id(str(raw), "CWE-")
            if norm:
                _append_unique(entry["cwes"], norm)

        # CAPECs
        for raw in self._iter_field(record, ("capec", "capecs", "CAPEC")):
            norm = self._normalise_id(str(raw), "CAPEC-")
            if norm:
                _append_unique(entry["capecs"], norm)

        # ATT&CK techniques
        for raw in self._iter_field(
            record, ("technique", "techniques", "attack_techniques", "attack")
        ):
            norm = self._normalise_technique(str(raw))
            if norm:
                _append_unique(entry["attack_techniques"], norm)

    # ------------------------------------------------------------------ #
    # String normalisation helpers                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_cve(text: str) -> str | None:
        """Return a canonical CVE ID (e.g. ``'CVE-2023-36632'``) or None."""
        import re

        match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
        return match.group(0).upper() if match else None

    @staticmethod
    def _normalise_id(text: str, prefix: str) -> str:
        """Ensure an ID has the expected prefix and numeric part."""
        import re

        upper = text.upper().strip()
        num_match = re.search(r"\d+", upper)
        if not num_match:
            return ""
        num = num_match.group(0)
        if upper.startswith(prefix):
            return f"{prefix}{num}"
        return f"{prefix}{num}"

    @staticmethod
    def _normalise_technique(text: str) -> str:
        """Return an ATT&CK technique ID (e.g. ``'T1190'``) or empty string."""
        import re

        match = re.search(r"T\d{4}(?:\.\d{3})?", text, re.IGNORECASE)
        return match.group(0).upper() if match else ""

    @staticmethod
    def _iter_field(record: dict[str, Any], keys: tuple[str, ...]):
        """Yield string values from the first matching key in *record*."""
        for key in keys:
            val = record.get(key)
            if val is None:
                continue
            if isinstance(val, list):
                yield from val
            else:
                yield val
            return  # stop after first matching key


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------

def _append_unique(lst: list[str], value: str) -> None:
    """Append *value* to *lst* if not already present (case-sensitive)."""
    if value and value not in lst:
        lst.append(value)
