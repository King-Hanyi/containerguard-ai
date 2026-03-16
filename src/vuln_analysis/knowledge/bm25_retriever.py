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

from rank_bm25 import BM25Okapi

class BM25Retriever:
    def __init__(self):
        self._index = None
        self._documents = []
        self._corpus = []

    def build_index(self, cve_entries: list[dict]) -> None:
        self._documents = cve_entries
        self._corpus = []
        for entry in cve_entries:
            description = entry.get("description", "")
            tokens = description.lower().split()
            self._corpus.append(tokens)
        
        if self._corpus:
            self._index = BM25Okapi(self._corpus)
        else:
            self._index = None

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not self._index:
            return []
            
        tokenized_query = query.lower().split()
        scores = self._index.get_scores(tokenized_query)
        
        results = []
        for i, score in enumerate(scores):
            results.append({
                "cve_id": self._documents[i].get("cve_id", ""),
                "description": self._documents[i].get("description", ""),
                "score": round(float(score), 4)
            })
            
        results = sorted(results, key=lambda x: x["score"], reverse=True)
        return results[:top_k]
