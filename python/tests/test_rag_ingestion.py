import unittest

from RAG.ingestion import SourceDocument, build_chunks, chunk_text


class SentenceChunkingTests(unittest.TestCase):
    def test_chunks_end_on_sentence_boundaries_and_share_trailing_sentences(self):
        sentences = [f"Sentence number {i} has exactly seven words." for i in range(30)]
        chunks = chunk_text(" ".join(sentences), chunk_size=40, overlap=16)

        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertTrue(chunk.endswith("words."))
            self.assertLessEqual(len(chunk.split()), 40)
        second_start = chunks[1].split(". ")[0].rstrip(".")
        self.assertIn(second_start, chunks[0])
        self.assertNotEqual(chunks[1], chunks[0])
        self.assertEqual(" ".join(chunks).count("Sentence number 29 "), 1)

    def test_all_content_is_covered(self):
        sentences = [f"Fact {i} is important." for i in range(60)]
        joined = " ".join(chunk_text(" ".join(sentences), chunk_size=30, overlap=8))
        for sentence in sentences:
            self.assertIn(sentence, joined)


class ChunkTitleTests(unittest.TestCase):
    def test_later_chunks_keep_the_document_title(self):
        body = " ".join(f"word{i}" for i in range(500))
        doc = SourceDocument(
            path="base/mitre_attack/hf_0463.md",
            category="mitre_attack",
            content=f"# What is the technique, T1566.001 Phishing: Spearphishing Attachment, in MITRE? {body}",
            metadata={},
        )

        chunks = build_chunks([doc])

        self.assertGreater(len(chunks), 2)
        title = "What is the technique, T1566.001 Phishing: Spearphishing Attachment, in MITRE"
        self.assertTrue(chunks[0]["text"].startswith("# What is the technique"))
        for chunk in chunks[1:]:
            self.assertTrue(chunk["text"].startswith(f"{title}: "))

    def test_markdown_pattern_title_is_cut_before_description(self):
        body = " ".join(f"word{i}" for i in range(500))
        doc = SourceDocument(
            path="base/attack_patterns/T1564.008.md",
            category="attack_patterns",
            content=f"# T1564.008 - Email Hiding Rules\n## Description\n{body}",
            metadata={},
        )

        chunks = build_chunks([doc])

        self.assertTrue(chunks[1]["text"].startswith("T1564.008 - Email Hiding Rules: "))

    def test_documents_without_heading_are_left_unchanged(self):
        doc = SourceDocument(
            path="policies/p.md", category="policies",
            content=" ".join(f"w{i}" for i in range(500)), metadata={},
        )

        self.assertTrue(build_chunks([doc])[1]["text"].startswith("w"))


if __name__ == "__main__":
    unittest.main()
