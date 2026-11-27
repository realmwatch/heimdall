-- Per-org: the local account a change-management tool's agent runs sudo
-- as. While a host is in an open patch plan, that account's local sudo
-- doesn't count toward privileged_access. Empty (the default): off.
ALTER TABLE ip_policies ADD COLUMN agent_account TEXT NOT NULL DEFAULT '';
