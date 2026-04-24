-- Optional pgvector extension and embedding columns for the analysis pipeline
-- (sentence-transformers / all-MiniLM-L6-v2, 384 dimensions).
--
-- This migration is separate from 0001_init.sql so operators who do not run
-- the analysis service can skip it. pgvector is available on RDS Postgres
-- and via the `pgvector/pgvector` container image used in docker-compose.yml.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS event_embeddings (
    event_id   BIGINT PRIMARY KEY REFERENCES events (id) ON DELETE CASCADE,
    model      TEXT NOT NULL,          -- 'all-MiniLM-L6-v2' or similar
    embedding  vector(384) NOT NULL,
    computed_ms BIGINT NOT NULL
);

-- HNSW index for approximate nearest-neighbour search. cosine distance for
-- sentence-transformer embeddings; tune ef_search at query time if recall is
-- insufficient on small corpora.
CREATE INDEX IF NOT EXISTS event_embeddings_hnsw_idx
    ON event_embeddings
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
