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
