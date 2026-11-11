-- The Amp project an Amp agent's hand-offs start their threads in, for a
-- repository, when an operator picks one: it wins over matching the
-- project's repository. repo is handoff.RepoKey (github.com/acme/app), so
-- every site on the repository shares it. No row: matched automatically.
CREATE TABLE amp_projects (
    org_id     INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    repo       TEXT    NOT NULL CHECK (length(repo) BETWEEN 1 AND 512),
    agent      TEXT    NOT NULL CHECK (length(agent) BETWEEN 1 AND 64),
    project_id TEXT    NOT NULL CHECK (length(project_id) BETWEEN 8 AND 64),
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (org_id, repo, agent)
) STRICT, WITHOUT ROWID;
