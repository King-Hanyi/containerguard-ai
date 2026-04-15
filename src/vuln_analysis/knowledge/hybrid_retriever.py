# Copyright 2026 ContainerGuard Authors
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

from vuln_analysis.knowledge.bm25_retriever import BM25Retriever
from typing import Any

class KnowledgeGraph:
    """Mock interface to allow typing, replace with actual import later."""
    def query_attack_chain(self, cve_id: str) -> list[str]:
        pass
        
    def get_related_cves(self, cwe_id: str) -> list[str]:
        pass

class HybridRetriever:
    def __init__(self, bm25: BM25Retriever, kg: KnowledgeGraph | Any):
        self.bm25 = bm25
        self.kg = kg

    def search(self, query: str, cve_id: str = "", top_k: int = 5) -> list[dict]:
        k = 60
        scores = {}

        bm25_results = self.bm25.search(query, top_k=top_k * 2)
        for rank, res in enumerate(bm25_results, 1):
            cid = res.get("cve_id")
            if cid:
                scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + rank)

        kg_results = []
        if cve_id:
            cwes = self.kg.query_attack_chain(cve_id)
            if cwes:
                for cwe in cwes:
                    related_cves = self.kg.get_related_cves(cwe)
                    if related_cves:
                        for rcve in related_cves:
                            if rcve not in kg_results:
                                kg_results.append(rcve)
        
        for rank, cid in enumerate(kg_results, 1):
            if cid:
                scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + rank)

        sorted_results = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        final_results = []
        for cid, score in sorted_results[:top_k]:
            final_results.append({
                "cve_id": cid,
                "rrf_score": round(score, 6)
            })

        return final_results
