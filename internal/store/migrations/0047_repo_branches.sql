-- The branch an operator made a repository's default target for hand-offs
-- ("Make dev this repository's default" on the confirm page): the confirm
-- page and "All N" preselect it instead of the repository's default
-- branch, while it's one of the sites' known branches. repo is
-- handoff.RepoKey (github.com/acme/app), as for amp_projects, so every
-- site on the repository shares it. No row: the repository's own default.
CREATE TABLE repo_branches (
    org_id     INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    repo       TEXT    NOT NULL CHECK (length(repo) BETWEEN 1 AND 512),
    branch     TEXT    NOT NULL CHECK (length(branch) BETWEEN 1 AND 200),
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (org_id, repo)
) STRICT, WITHOUT ROWID;
