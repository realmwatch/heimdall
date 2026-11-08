-- The systemd services named *-agent installed on a host, from the
-- collector's X-Heimdall-Agents header: comma-separated, "-" for none,
-- NULL until a collector that reports them has pushed.
ALTER TABLE hosts ADD COLUMN agents TEXT;
