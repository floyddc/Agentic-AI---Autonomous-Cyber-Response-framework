import unittest
from unittest.mock import MagicMock, patch

import config
from RAG.retriever import expand_hits, fuse_rankings, lexical_rank, merge_chunks, retrieve, select_hits


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

        self.assertEqual(results, reranked_hits[1:])
        self.assertEqual(metrics["candidate_k"], min(config.RERANK_CANDIDATES, 12))
        self.assertEqual(metrics["candidate_results"][0]["source"], "mitre/T1234.md")
        self.assertEqual(metrics["candidate_results"][0]["rank"], 1)
        self.assertEqual(metrics["reranked_results"], [{
            "rank": 1,
            "source": "playbooks/endpoint.md",
            "category": "procedures",
            "rerank_score": 0.91,
            "lexical_rank": None,
            "lexical_score": None,
        }, {
            "rank": 2,
            "source": "mitre/T1234.md",
            "category": "mitre_attack",
            "rerank_score": 0.32,
            "lexical_rank": None,
            "lexical_score": None,
        }])
        self.assertEqual(collection.query.call_args.kwargs["n_results"], min(config.RERANK_CANDIDATES, 12))
        embed_query.assert_called_once_with("alert query")
        rerank.assert_called_once_with("alert query", unittest.mock.ANY, top_k=2)
        self.assertEqual(metrics["selected_results"][0]["source"], "mitre/T1234.md")


class FuseRankingsTests(unittest.TestCase):
    @staticmethod
    def _hit(name, score=0.0):
        return {"text": name, "metadata": {"source": name}, "rerank_score": score}

    def test_a_hit_ranked_first_by_the_embedding_is_not_overridden_by_a_single_reranker_vote(self):
        vector = [self._hit(n) for n in ("rel", "n1", "n2", "n3", "n4", "n5", "n6", "up")]
        reranked = [self._hit(n) for n in ("up", "n1", "rel", "n2", "n3", "n4", "n5", "n6")]

        order = [h["text"] for h in fuse_rankings(vector, reranked, rerank_weight=1.0)]

        self.assertLess(order.index("rel"), order.index("up"))

    def test_agreement_between_both_rankings_wins(self):
        vector = [self._hit(name) for name in ("a", "b", "c")]
        reranked = [self._hit(name) for name in ("a", "c", "b")]

        fused = fuse_rankings(vector, reranked, rerank_weight=1.0)

        self.assertEqual(fused[0]["text"], "a")
        self.assertEqual({h["text"]: h["vector_rank"] for h in fused}, {"a": 1, "b": 2, "c": 3})

    def test_zero_weight_keeps_the_vector_order(self):
        vector = [self._hit(name) for name in ("a", "b", "c")]
        reranked = [self._hit(name) for name in ("c", "b", "a")]

        self.assertEqual([h["text"] for h in fuse_rankings(vector, reranked, rerank_weight=0.0)], ["a", "b", "c"])

    def test_lexical_vote_can_promote_an_exact_evidence_match(self):
        hits = [
            {"text": "Collect certificate metadata and monitor trust providers.", "metadata": {"source": "trust.md"}},
            {"text": "Antivirus can detect malicious files downloaded and executed on the user's computer.", "metadata": {"source": "execution.md"}},
            {"text": "Compile source code after delivery using native utilities.", "metadata": {"source": "compile.md"}},
        ]
        ranked = lexical_rank("file executable downloaded user malicious", hits)
        self.assertEqual(ranked[0]["metadata"]["source"], "execution.md")
        self.assertLess(ranked[0]["lexical_rank"], ranked[1]["lexical_rank"])

    def test_rank_fusion_uses_candidate_identity_not_document_text(self):
        vector = [
            {"text": "same body", "metadata": {"source": "doc.md", "chunk_index": 0}},
            {"text": "same body", "metadata": {"source": "doc.md", "chunk_index": 1}},
        ]
        lexical = list(reversed(vector))
        reranked = list(reversed(vector))
        fused = fuse_rankings(vector, reranked, lexical, rerank_weight=0.0, lexical_weight=2.0)
        self.assertEqual(fused[0]["metadata"]["chunk_index"], 1)


class ExpandHitsTests(unittest.TestCase):
    def test_merge_drops_title_and_overlapping_sentences(self):
        merged = merge_chunks(
            "Intro sentence. Shared sentence.",
            "Title T1: Shared sentence. Detection steps here.",
            title="Title T1",
        )
        self.assertEqual(merged, "Intro sentence. Shared sentence. Detection steps here.")

    def test_expands_only_the_requested_top_hits_with_the_next_chunk(self):
        collection = MagicMock()
        collection.get.return_value = {"documents": ["Title T1: Detection steps here."]}
        hits = [
            {"text": "Intro sentence.", "metadata": {"source": "a.md", "chunk_index": 0, "title": "Title T1"}},
            {"text": "Other.", "metadata": {"source": "b.md", "chunk_index": 0}},
        ]

        expand_hits(collection, hits, 1)

        self.assertEqual(hits[0]["text"], "Intro sentence. Detection steps here.")
        self.assertEqual(hits[1]["text"], "Other.")
        collection.get.assert_called_once_with(ids=["a.md::1"], include=["documents"])

    def test_last_chunk_and_lookup_errors_leave_the_hit_unchanged(self):
        collection = MagicMock()
        collection.get.return_value = {"documents": []}
        hit = {"text": "Last chunk.", "metadata": {"source": "a.md", "chunk_index": 3}}
        expand_hits(collection, [hit], 1)
        self.assertEqual(hit["text"], "Last chunk.")

        collection.get.side_effect = RuntimeError("boom")
        expand_hits(collection, [hit], 1)
        self.assertEqual(hit["text"], "Last chunk.")


class SelectHitsTests(unittest.TestCase):
    @staticmethod
    def _hit(source, score, text="text"):
        return {"text": text, "metadata": {"source": source}, "rerank_score": score}

    def test_keeps_one_hit_per_technique_across_sources(self):
        hits = [
            self._hit("base/mitre_attack/hf_0463_what_is_the_technique_t1566_001_phishing_spearphishing_attac.md", 2.0),
            self._hit("base/attack_patterns/T1566.001_Spearphishing_Attachment.md", 1.5),
            self._hit("base/attack_patterns/T1221_Template_Injection.md", 1.0),
        ]

        selected = select_hits(hits, top_k=5, min_score=0.0)

        self.assertEqual([h["rerank_score"] for h in selected], [2.0, 1.0])

    def test_drops_weak_hits_but_always_keeps_the_best(self):
        weak = [self._hit("a.md", -1.0), self._hit("b.md", -2.0)]
        self.assertEqual(select_hits(weak, top_k=5, min_score=0.0), weak[:1])

        mixed = [self._hit("a.md", 1.0), self._hit("b.md", -0.1), self._hit("c.md", 0.5)]
        self.assertEqual(select_hits(mixed, top_k=5, min_score=0.0), mixed[:1])

    def test_drops_hits_far_below_the_best_one(self):
        hits = [self._hit("a.md", 3.5), self._hit("b.md", 2.5), self._hit("c.md", 1.2)]
        self.assertEqual(select_hits(hits, top_k=5, min_score=0.0, margin=2.0), hits[:2])

    def test_caps_at_top_k(self):
        hits = [self._hit(f"{i}.md", 5.0 - i) for i in range(5)]
        self.assertEqual(len(select_hits(hits, top_k=2, min_score=0.0)), 2)


if __name__ == "__main__":
    unittest.main()
