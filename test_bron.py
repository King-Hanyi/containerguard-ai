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

"""End-to-end smoke test for the BRON knowledge graph pipeline.

Usage (from the project root directory)::

    python test_bron.py

The script assumes the BRON repository has already been cloned into the
project root (i.e. ``<project_root>/BRON/`` exists).
"""

import json
import logging
import os
import sys

# ---------------------------------------------------------------------------
# Ensure project src is on the path when running directly (without `pip install`)
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_SCRIPT_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from vuln_analysis.knowledge.bron_loader import BRONLoader
from vuln_analysis.knowledge.knowledge_graph import KnowledgeGraph

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("test_bron")

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _divider(title: str) -> None:
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


# ---------------------------------------------------------------------------
# Main test routine
# ---------------------------------------------------------------------------

def main() -> None:
    # BRON directory is expected at <project_root>/BRON/
    bron_dir = os.path.join(_SCRIPT_DIR, "BRON")

    _divider("Step 1 – Loading BRON dataset")
    print(f"BRON path : {bron_dir}")

    loader = BRONLoader()
    cve_data: dict = loader.load(bron_dir)

    print(f"Total CVEs loaded : {len(cve_data)}")
    if cve_data:
        sample_key = next(iter(cve_data))
        print(f"Sample entry      : {sample_key} → {cve_data[sample_key]}")
    else:
        print(
            "[WARN] No CVE data was parsed. "
            "The BRON dataset may use a different file layout or the "
            "directory is empty. The graph will be initialised with no data."
        )

    _divider("Step 2 – Building KnowledgeGraph")
    kg = KnowledgeGraph(cve_data)
    stats = kg.stats()
    print(json.dumps(stats, indent=2))

    # -----------------------------------------------------------------------
    # Target CVE query
    # -----------------------------------------------------------------------
    target_cve = "CVE-2023-36632"

    _divider(f"Step 3 – query_attack_chain('{target_cve}')")
    chain = kg.query_attack_chain(target_cve)
    print(json.dumps(chain, indent=2))

    # -----------------------------------------------------------------------
    # Reverse CWE lookup – use the first CWE found in the chain (if any)
    # -----------------------------------------------------------------------
    _divider("Step 4 – get_related_cves(cwe_id)")
    cwe_to_query: str | None = chain["cwes"][0] if chain["cwes"] else None

    if cwe_to_query:
        related = kg.get_related_cves(cwe_to_query)
        print(f"CWE queried : {cwe_to_query}")
        print(f"Related CVEs ({len(related)} total):")
        for cve in related[:20]:          # cap output to first 20
            print(f"  • {cve}")
        if len(related) > 20:
            print(f"  … and {len(related) - 20} more")
    else:
        # Fallback: demo with a well-known CWE
        fallback_cwe = "CWE-20"
        print(
            f"No CWEs found for {target_cve}. "
            f"Falling back to demo query: {fallback_cwe}"
        )
        related = kg.get_related_cves(fallback_cwe)
        print(f"Related CVEs for {fallback_cwe} ({len(related)} total):")
        for cve in related[:20]:
            print(f"  • {cve}")

    _divider("Done")
    print("All steps completed successfully.\n")


if __name__ == "__main__":
    main()
