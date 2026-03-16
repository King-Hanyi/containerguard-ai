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

import pytest
from src.vuln_analysis.knowledge.bm25_retriever import BM25Retriever
from src.vuln_analysis.knowledge.hybrid_retriever import HybridRetriever, KnowledgeGraph

class MockKnowledgeGraph(KnowledgeGraph):
    def query_attack_chain(self, cve_id: str) -> list[str]:
        if cve_id == "CVE-2021-44228":
            return ["CWE-502"]
        return []

    def get_related_cves(self, cwe_id: str) -> list[str]:
        if cwe_id == "CWE-502":
            return ["CVE-2021-44228", "CVE-2022-22965"]
        return []

class TestBM25Retriever:
    def setup_method(self):
        self.retriever = BM25Retriever()
        cve_entries = [
            {"cve_id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."},
            {"cve_id": "CVE-2022-22965", "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding."},
            {"cve_id": "CVE-2014-0160", "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory."}
        ]
        self.retriever.build_index(cve_entries)

    def test_search_log4j(self):
        results = self.retriever.search("log4j JNDI")
        assert len(results) > 0
        assert results[0]["cve_id"] == "CVE-2021-44228"

    def test_search_openssl(self):
        results = self.retriever.search("openssl heartbeat")
        assert len(results) > 0
        assert results[0]["cve_id"] == "CVE-2014-0160"

    def test_empty_index(self):
        empty_retriever = BM25Retriever()
        results = empty_retriever.search("test")
        assert results == []

    def test_hybrid_retriever(self):
        kg = MockKnowledgeGraph()
        hybrid_retriever = HybridRetriever(bm25=self.retriever, kg=kg)
        
        results = hybrid_retriever.search("log4j JNDI", cve_id="CVE-2021-44228", top_k=2)
        assert len(results) > 0
        assert results[0]["cve_id"] == "CVE-2021-44228"
        assert "rrf_score" in results[0]
        assert isinstance(results[0]["rrf_score"], float)
