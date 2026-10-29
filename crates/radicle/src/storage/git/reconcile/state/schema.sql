-- Reconciliation's progress, beside the COB cache it rebuilds. Created if
-- absent; the cache's own schema version is untouched.

-- Each repository under repair: the version of its refs when its repair
-- began, and the steps it has finished.
create table if not exists "reconcile_repository" (
  "rid"           text      primary key not null,
  "version"       text      not null,
  -- Comma-separated.
  "steps"         text      not null
) strict;

-- The checkpoint of each namespace check: bound to the namespace's version
-- and the check's authority.
create table if not exists "reconcile_namespace" (
  "rid"           text      not null,
  "namespace"     text      not null,
  "version"       text      not null,
  -- `owner` or `none`.
  "authority"     text      not null,
  -- The last ref checked.
  "after"         text,
  "stale"         integer   not null,
  primary key ("rid", "namespace")
) strict;

-- The unit in progress: one row at most.
create table if not exists "reconcile_unit" (
  "id"            integer   primary key not null check ("id" = 1),
  "rid"           text      not null,
  "kind"          text      not null,
  "position"      text      not null,
  "attempts"      integer   not null
) strict;

-- A cache rebuild's staged COBs: the rows publication swaps in.
create table if not exists "rebuild_staging" (
  "rid"           text      not null,
  -- `issue` or `patch`.
  "kind"          text      not null,
  "id"            text      not null,
  -- The COB as the cache writes it.
  "json"          text      not null,
  primary key ("rid", "kind", "id")
) strict;

-- A cache rebuild's worklist: each COB's tips, one a remote, taken from the
-- remotes' verified signed refs in one scan. Bound to the repository's
-- version, through its scan.
create table if not exists "rebuild_worklist" (
  "rid"           text      not null,
  -- `issue` or `patch`.
  "kind"          text      not null,
  "id"            text      not null,
  "remote"        text      not null,
  "tip"           text      not null,
  primary key ("rid", "kind", "id", "remote")
) strict;

-- A cache rebuild's scan of its remotes: the version it is bound to, the
-- last remote scanned, and whether every remote has been.
create table if not exists "rebuild_scan" (
  "rid"           text      primary key not null,
  "version"       text      not null,
  "after"         text,
  "complete"      integer   not null
) strict;

-- A cache rebuild's checkpoint: the kind it is at, and the last COB of it
-- staged. Bound to the repository's version.
create table if not exists "reconcile_cache" (
  "rid"           text      primary key not null,
  "version"       text      not null,
  "kind"          text      not null,
  "after"         text
) strict;
