import unittest
from unittest.mock import MagicMock, patch

from RAG.retriever import retrieve


class RetrieverTests(unittest.TestCase):
    @patch("RAG.retriever.rerank")
    @patch("RAG.retriever.embed_query", return_value=[0.1, 0.2])
    @patch("RAG.retriever.get_collection")
    def test_metrics_expose_candidates_before_and_after_reranking(
        self, get_collection, embed_query, rerank
    ):
        collection = MagicMock()
        collection.count.return_value = 12
        collection.query.return_value = {
            "documents": [["MITRE technique A", "incident response playbook"]],
            "metadatas": [[
                {"source": "mitre/T1234.md", "category": "mitre_attack"},
                {"source": "playbooks/endpoint.md", "category": "procedures"},
            ]],
            "distances": [[0.12, 0.2]],
        }
        get_collection.return_value = collection

        reranked_hits = [
            {
                "text": "incident response playbook",
                "metadata": {"source": "playbooks/endpoint.md", "category": "procedures"},
                "distance": 0.2,
                "rerank_score": 0.91,
            },
            {
                "text": "MITRE technique A",
                "metadata": {"source": "mitre/T1234.md", "category": "mitre_attack"},
                "distance": 0.12,
                "rerank_score": 0.32,
            },
        ]
        rerank.return_value = reranked_hits
        metrics = {}

        results = retrieve(
            "alert query",
            customer_id=1,
            top_k=1,
            metrics=metrics,
        )

        self.assertEqual(results, reranked_hits[:1])
        self.assertEqual(metrics["candidate_k"], 10)
        self.assertEqual(metrics["candidate_results"][0]["source"], "mitre/T1234.md")
        self.assertEqual(metrics["candidate_results"][0]["rank"], 1)
        self.assertEqual(metrics["reranked_results"], [{
            "rank": 1,
            "source": "playbooks/endpoint.md",
            "category": "procedures",
            "rerank_score": 0.91,
        }, {
            "rank": 2,
            "source": "mitre/T1234.md",
            "category": "mitre_attack",
            "rerank_score": 0.32,
        }])
        self.assertEqual(collection.query.call_args.kwargs["n_results"], 10)
        embed_query.assert_called_once_with("alert query")
        rerank.assert_called_once_with("alert query", unittest.mock.ANY, top_k=2)


if __name__ == "__main__":
    unittest.main()
