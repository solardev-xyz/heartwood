-- Repositories reconciliation couldn't repair, one record each, kept until
-- the repository is removed.
create table if not exists "quarantine" (
  -- The repository.
  "rid"           text      primary key not null,
  -- The record's own ID, 32 hex digits, unique to it.
  "qid"           text      not null unique,
  -- `cache` or `namespace`.
  "kind"          text      not null check ("kind" in ('cache', 'namespace')),
  -- The step that couldn't finish.
  "step"          text      not null,
  -- The unit in progress, if one was.
  "unit"          text,
  -- What was found.
  "evidence"      text      not null,
  -- When, in milliseconds since the epoch.
  "since"         integer   not null
) strict;
