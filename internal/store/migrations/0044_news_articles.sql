-- News sources are either a curated incident list (each download replaces
-- the source's incidents) or an RSS/Atom feed of articles (articles scroll
-- off the feed, so they're kept until they age out). published_at is when
-- the source last published anything, so a source that has gone quiet
-- shows as quiet instead of looking like a calm week.
ALTER TABLE news_sources ADD COLUMN kind TEXT NOT NULL DEFAULT 'incidents' CHECK (kind IN ('incidents', 'articles'));
ALTER TABLE news_sources ADD COLUMN published_at TEXT;
