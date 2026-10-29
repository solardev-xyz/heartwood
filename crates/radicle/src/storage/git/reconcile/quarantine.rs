//! The record of the repositories reconciliation couldn't repair.
//!
//! It lives in a small database of its own, `node/reconcile.db`: not in
//! `cobs/cache.db`, which is derived data that may be deleted, and not in the
//! node's own database, whose schema stays heartwood's. A record is written
//! durably (WAL, `synchronous = FULL`), and stays until its repository is
//! removed with [`remove_repo`]: unseeding doesn't clear it.

use std::path::Path;
use std::str::FromStr;
use std::{fmt, time};

use localtime::LocalTime;
use sqlite as sql;
use thiserror::Error;

use crate::cob;
use crate::node::policy;
use crate::prelude::RepoId;
use crate::sql::transaction;

use super::dir::Dir;

/// The file, under the node's directory, that holds the record.
pub const QUARANTINE_DB_FILE: &str = "reconcile.db";

/// How long a write waits for the database's lock.
const DB_WRITE_TIMEOUT: time::Duration = time::Duration::from_secs(6);

/// The database's migrations: the first creates its table.
const MIGRATIONS: &[&str] = &[include_str!("quarantine/1.sql")];

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] sql::Error),
    #[error("invalid quarantine record: {0}")]
    Invalid(String),
    #[error("no record ID from the operating system's random generator: {0}")]
    Random(getrandom::Error),
    #[error("a new record's ID, {0}, is another record's: nothing was recorded")]
    Collision(Qid),
}

/// Why reconciliation couldn't repair a repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A COB, or the cache, can't be rebuilt. The repository's git data and
    /// the node's namespace are intact.
    Cache,
    /// A namespace the dirty marker names doesn't verify and can't be
    /// re-signed.
    Namespace,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Namespace => "namespace",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Kind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cache" => Ok(Self::Cache),
            "namespace" => Ok(Self::Namespace),
            other => Err(Error::Invalid(format!("unknown kind {other:?}"))),
        }
    }
}

/// A record's own ID: 128 random bits, created with the record. A removal
/// names the record it means by it, so that it never acts on a repository
/// quarantined, or cloned, again since.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Qid(u128);

impl Qid {
    /// A new ID: 128 bits from the operating system's cryptographic
    /// generator, independent of any generator the process seeds, so that no
    /// two records share one, even across a removal.
    fn random() -> Result<Self, Error> {
        #[cfg(test)]
        if let Some(qid) = tests::NEXT_QID.take() {
            return Ok(Self(qid));
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(Error::Random)?;
        Ok(Self(u128::from_be_bytes(bytes)))
    }
}

impl fmt::Display for Qid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Debug for Qid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Qid({self})")
    }
}

impl FromStr for Qid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!("not a qid: {s:?}")));
        }
        u128::from_str_radix(s, 16)
            .map(Self)
            .map_err(|_| Error::Invalid(format!("not a qid: {s:?}")))
    }
}

/// One quarantined repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub rid: RepoId,
    pub qid: Qid,
    pub kind: Kind,
    /// The step that couldn't finish.
    pub step: String,
    /// The unit in progress, if one was.
    pub unit: Option<String>,
    /// What was found.
    pub evidence: String,
    /// When it was quarantined.
    pub since: LocalTime,
}

/// The quarantine record, `node/reconcile.db`.
pub struct Quarantine {
    db: sql::ConnectionThreadSafe,
}

impl fmt::Debug for Quarantine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quarantine").finish()
    }
}

impl Quarantine {
    /// Opens the record at `path`, creating it if there is none, in WAL mode
    /// and with `synchronous = FULL`: a record written is on disk.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db = sql::Connection::open_thread_safe(path)?;
        db.set_busy_timeout(DB_WRITE_TIMEOUT.as_millis() as usize)?;
        db.execute("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        migrate(&db)?;
        Ok(Self { db })
    }

    /// Quarantines `rid`, unless it is already: its record either way. A
    /// repository already quarantined keeps its first record. A new record's
    /// ID that another record holds is refused, with nothing recorded.
    pub fn quarantine(
        &mut self,
        rid: RepoId,
        kind: Kind,
        step: &str,
        unit: Option<&str>,
        evidence: &str,
        since: LocalTime,
    ) -> Result<Record, Error> {
        transaction(&self.db, |db| {
            if let Some(record) = get(db, &rid)? {
                return Ok(record);
            }
            let qid = Qid::random()?;
            let mut stmt = db.prepare("SELECT 1 FROM quarantine WHERE qid = ?1")?;
            stmt.bind((1, qid.to_string().as_str()))?;
            if stmt.next()? == sql::State::Row {
                return Err(Error::Collision(qid));
            }
            let mut stmt = db.prepare(
                "INSERT INTO quarantine (rid, qid, kind, step, unit, evidence, since)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            stmt.bind((1, &rid))?;
            stmt.bind((2, qid.to_string().as_str()))?;
            stmt.bind((3, kind.as_str()))?;
            stmt.bind((4, step))?;
            stmt.bind((5, unit))?;
            stmt.bind((6, evidence))?;
            stmt.bind((7, i64::try_from(since.as_millis()).unwrap_or(i64::MAX)))?;
            stmt.next()?;
            get(db, &rid)?.ok_or_else(|| Error::Invalid(format!("no record for {rid}")))
        })
    }

    /// The record of `rid`, if it is quarantined.
    pub fn get(&self, rid: &RepoId) -> Result<Option<Record>, Error> {
        get(&self.db, rid)
    }

    /// How many repositories are quarantined.
    pub fn count(&self) -> Result<usize, Error> {
        let mut stmt = self.db.prepare("SELECT COUNT(*) FROM quarantine")?;
        stmt.next()?;
        Ok(stmt.read::<i64, _>(0)? as usize)
    }

    /// The records of page `page`, `size` a page, in the order of their
    /// repositories' IDs.
    pub fn page(&self, page: usize, size: usize) -> Result<Vec<Record>, Error> {
        let mut stmt = self.db.prepare(
            "SELECT rid, qid, kind, step, unit, evidence, since FROM quarantine
             ORDER BY rid LIMIT ?1 OFFSET ?2",
        )?;
        stmt.bind((1, size as i64))?;
        stmt.bind((2, page.saturating_mul(size) as i64))?;
        stmt.into_iter().map(|row| record(&row?)).collect()
    }

    /// Clears the record of `rid`, if it has `qid`: whether it did.
    fn clear(&mut self, rid: &RepoId, qid: Qid) -> Result<bool, Error> {
        let mut stmt = self
            .db
            .prepare("DELETE FROM quarantine WHERE rid = ?1 AND qid = ?2")?;
        stmt.bind((1, rid))?;
        stmt.bind((2, qid.to_string().as_str()))?;
        stmt.next()?;
        Ok(self.db.change_count() > 0)
    }

    /// The schema version: how many migrations have run.
    pub fn version(&self) -> Result<usize, Error> {
        version(&self.db)
    }
}

fn get(db: &sql::Connection, rid: &RepoId) -> Result<Option<Record>, Error> {
    let mut stmt = db.prepare(
        "SELECT rid, qid, kind, step, unit, evidence, since FROM quarantine
         WHERE rid = ?1",
    )?;
    stmt.bind((1, rid))?;
    match stmt.into_iter().next() {
        Some(row) => record(&row?).map(Some),
        None => Ok(None),
    }
}

fn record(row: &sql::Row) -> Result<Record, Error> {
    Ok(Record {
        rid: row.try_read::<RepoId, _>("rid")?,
        qid: row.try_read::<&str, _>("qid")?.parse()?,
        kind: row.try_read::<&str, _>("kind")?.parse()?,
        step: row.try_read::<&str, _>("step")?.to_owned(),
        unit: row.try_read::<Option<&str>, _>("unit")?.map(str::to_owned),
        evidence: row.try_read::<&str, _>("evidence")?.to_owned(),
        since: LocalTime::from_millis(row.try_read::<i64, _>("since")?.max(0) as u128),
    })
}

fn version(db: &sql::Connection) -> Result<usize, Error> {
    let mut stmt = db.prepare("PRAGMA user_version")?;
    stmt.next()?;
    Ok(stmt.read::<i64, _>(0)? as usize)
}

fn migrate(db: &sql::Connection) -> Result<usize, Error> {
    let mut current = version(db)?;
    for (i, migration) in MIGRATIONS.iter().enumerate().skip(current) {
        transaction(db, |db| {
            db.execute(migration)?;
            db.execute(format!("PRAGMA user_version = {}", i + 1))?;
            Ok::<_, Error>(())
        })?;
        current = i + 1;
    }
    Ok(current)
}

/// What [`remove_repo`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// The repository was removed, and its record cleared.
    Removed,
    /// No record of the repository has that `qid`: nothing was removed.
    NotQuarantined,
}

#[derive(Debug, Error)]
pub enum RemoveError {
    #[error(transparent)]
    Quarantine(#[from] Error),
    #[error(transparent)]
    Policy(#[from] policy::store::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cache(#[from] sql::Error),
}

/// Removes the quarantined repository `rid` of the storage at `storage`, if
/// its record has `qid`: the only way out of quarantine. With no record of
/// `rid`, or one with another `qid`, nothing is touched. Otherwise, in order,
/// each step durable before the next:
///
/// 1. it unseeds the repository, in `policies`;
/// 2. it deletes `storage/<rid>`, following no links (a link of that name is
///    removed itself, a junction included), and flushes the storage
///    directory, so that the deletion is on disk;
/// 3. it deletes the repository's rows of the COB cache, `cache`;
/// 4. it clears the record.
///
/// Each step is idempotent, and the record, with its `qid`, stays until the
/// last: a removal cut off at any point completes when run again with the
/// same `qid`. Run it with the repository shut to the node.
pub fn remove_repo(
    quarantine: &mut Quarantine,
    policies: &mut policy::store::StoreWriter,
    storage: &Path,
    cache: &mut cob::cache::StoreWriter,
    rid: RepoId,
    qid: Qid,
) -> Result<Removal, RemoveError> {
    if quarantine.get(&rid)?.is_none_or(|record| record.qid != qid) {
        return Ok(Removal::NotQuarantined);
    }
    policies.unseed(&rid)?;

    let root = Dir::open_root(storage)?;
    let name = rid.canonical();
    let name = std::ffi::OsStr::new(&name);
    if !root.remove_tree(name)? {
        root.remove_file(name)?;
    }
    // The record keeps the repository out until the deletion is on disk: a
    // flush that fails leaves it, for the removal to be run again.
    sync(&root)?;

    cob::cache::Remove::<cob::issue::Issue>::remove_all(cache, &rid)?;
    cob::cache::Remove::<cob::patch::Patch>::remove_all(cache, &rid)?;

    quarantine.clear(&rid, qid)?;
    Ok(Removal::Removed)
}

/// Flushes the storage directory `root`.
fn sync(root: &Dir) -> std::io::Result<()> {
    #[cfg(test)]
    if tests::FAIL_SYNC.get() {
        return Err(std::io::Error::other("the flush failed (test)"));
    }
    root.sync()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        /// The ID the next record takes, if set.
        pub(super) static NEXT_QID: Cell<Option<u128>> = const { Cell::new(None) };
        /// Whether flushing the storage directory fails.
        pub(super) static FAIL_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    use crate::cob::cache::migrate;
    use crate::node::policy::Scope;
    use crate::test::arbitrary;

    fn rid() -> RepoId {
        arbitrary::r#gen(1)
    }

    fn pragma(db: &Quarantine, name: &str) -> String {
        let mut stmt = db.db.prepare(format!("PRAGMA {name}")).unwrap();
        stmt.next().unwrap();
        match stmt.read::<sql::Value, _>(0).unwrap() {
            sql::Value::String(s) => s,
            sql::Value::Integer(i) => i.to_string(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_record_is_durable_and_outlives_its_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(QUARANTINE_DB_FILE);
        let (a, b) = (rid(), rid());
        let mut db = Quarantine::open(&path).unwrap();
        assert_eq!(pragma(&db, "journal_mode"), "wal");
        // `FULL` is 2.
        assert_eq!(pragma(&db, "synchronous"), "2");
        assert_eq!(db.version().unwrap(), MIGRATIONS.len());

        let since = LocalTime::from_millis(1_700_000_000_123);
        let first = db
            .quarantine(
                a,
                Kind::Namespace,
                "namespaces",
                Some("z6Mk..@refs/heads/x"),
                "unsigned refs/heads/x",
                since,
            )
            .unwrap();
        assert_eq!(first.rid, a);
        assert_eq!(first.kind, Kind::Namespace);
        assert_eq!(first.since, since);
        // Quarantined again, it keeps its first record.
        let again = db
            .quarantine(a, Kind::Cache, "cache", None, "another", LocalTime::now())
            .unwrap();
        assert_eq!(again, first);
        let other = db
            .quarantine(
                b,
                Kind::Cache,
                "cache",
                None,
                "a COB that doesn't load",
                since,
            )
            .unwrap();
        assert_ne!(other.qid, first.qid);
        drop(db);

        let db = Quarantine::open(&path).unwrap();
        assert_eq!(db.count().unwrap(), 2);
        assert_eq!(db.get(&a).unwrap(), Some(first));
        assert_eq!(db.get(&b).unwrap(), Some(other));
        assert_eq!(db.get(&rid()).unwrap(), None);
    }

    #[test]
    fn records_page_in_the_order_of_their_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = Quarantine::open(tmp.path().join(QUARANTINE_DB_FILE)).unwrap();
        let mut rids = (0..100).map(|_| rid()).collect::<Vec<_>>();
        for rid in &rids {
            db.quarantine(*rid, Kind::Cache, "cache", None, "", LocalTime::now())
                .unwrap();
        }
        rids.sort_by_key(|rid| rid.urn());
        let pages = (0..3)
            .map(|page| db.page(page, 64).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), [64, 36, 0]);
        let paged = pages.concat().iter().map(|r| r.rid).collect::<Vec<_>>();
        assert_eq!(paged, rids);
    }

    #[test]
    fn a_qid_reads_back_as_written() {
        let qid = Qid::random().unwrap();
        assert_eq!(qid.to_string().len(), 32);
        assert_eq!(qid.to_string().parse::<Qid>().unwrap(), qid);
        assert!("0123".parse::<Qid>().is_err());
        assert!("g".repeat(32).parse::<Qid>().is_err());
        assert!(format!("+{}", "0".repeat(31)).parse::<Qid>().is_err());
    }

    struct Removing {
        _tmp: tempfile::TempDir,
        storage: std::path::PathBuf,
        quarantine: Quarantine,
        policies: policy::store::StoreWriter,
        cache: cob::cache::StoreWriter,
        rid: RepoId,
        record: Record,
    }

    /// A quarantined repository: its directory in storage, seeded, with an
    /// issue and a patch in the COB cache. And another repository, its
    /// neighbour, the same but not quarantined.
    fn removing() -> (Removing, RepoId) {
        let tmp = tempfile::tempdir().unwrap();
        let storage = tmp.path().join("storage");
        let (rid, neighbour) = (rid(), rid());
        let mut policies = policy::store::StoreWriter::memory().unwrap();
        let cache = cob::cache::StoreWriter::memory()
            .unwrap()
            .with_migrations(migrate::ignore)
            .unwrap();
        for (i, rid) in [rid, neighbour].iter().enumerate() {
            std::fs::create_dir_all(storage.join(rid.canonical()).join("refs/heads")).unwrap();
            std::fs::write(storage.join(rid.canonical()).join("HEAD"), b"x").unwrap();
            policies.seed(rid, Scope::All).unwrap();
            cache
                .raw_query(|db| {
                    let mut stmt =
                        db.prepare("INSERT INTO issues (id, repo, issue) VALUES (?1, ?2, '{}');")?;
                    stmt.bind((1, format!("issue-{i}").as_str()))?;
                    stmt.bind((2, rid))?;
                    stmt.next()?;
                    let mut stmt =
                        db.prepare("INSERT INTO patches (id, repo, patch) VALUES (?1, ?2, '{}');")?;
                    stmt.bind((1, format!("patch-{i}").as_str()))?;
                    stmt.bind((2, rid))?;
                    stmt.next()?;
                    Ok::<_, sql::Error>(())
                })
                .unwrap();
        }
        let mut quarantine = Quarantine::open(tmp.path().join(QUARANTINE_DB_FILE)).unwrap();
        let record = quarantine
            .quarantine(
                rid,
                Kind::Namespace,
                "namespaces",
                None,
                "",
                LocalTime::now(),
            )
            .unwrap();
        (
            Removing {
                _tmp: tmp,
                storage,
                quarantine,
                policies,
                cache,
                rid,
                record,
            },
            neighbour,
        )
    }

    fn cache_rows(cache: &cob::cache::StoreWriter, rid: &RepoId) -> i64 {
        cache
            .raw_query(|db| {
                let mut stmt = db.prepare(
                    "SELECT (SELECT COUNT(*) FROM issues WHERE repo = ?1)
                          + (SELECT COUNT(*) FROM patches WHERE repo = ?1)",
                )?;
                stmt.bind((1, rid))?;
                stmt.next()?;
                stmt.read::<i64, _>(0)
            })
            .unwrap()
    }

    impl Removing {
        fn remove(&mut self, qid: Qid) -> Removal {
            remove_repo(
                &mut self.quarantine,
                &mut self.policies,
                &self.storage,
                &mut self.cache,
                self.rid,
                qid,
            )
            .unwrap()
        }

        /// Whether nothing of the repository is left: not its directory, its
        /// seeding policy, its cache rows, nor its record.
        fn gone(&self, rid: &RepoId) -> bool {
            !self.storage.join(rid.canonical()).exists()
                && !self.policies.is_seeding(rid).unwrap()
                && cache_rows(&self.cache, rid) == 0
                && self.quarantine.get(rid).unwrap().is_none()
        }

        fn intact(&self, rid: &RepoId) -> bool {
            self.storage.join(rid.canonical()).join("HEAD").exists()
                && self.policies.is_seeding(rid).unwrap()
                && cache_rows(&self.cache, rid) == 2
        }
    }

    #[test]
    fn a_removal_takes_its_record_s_qid() {
        let (mut f, neighbour) = removing();
        // Another qid: nothing is removed.
        assert_eq!(f.remove(Qid::random().unwrap()), Removal::NotQuarantined);
        assert!(f.intact(&f.rid));
        assert_eq!(f.quarantine.get(&f.rid).unwrap(), Some(f.record.clone()));

        assert_eq!(f.remove(f.record.qid), Removal::Removed);
        assert!(f.gone(&f.rid));
        assert!(f.intact(&neighbour));
        // Delivered again, the removal finds no record.
        assert_eq!(f.remove(f.record.qid), Removal::NotQuarantined);
    }

    #[test]
    fn a_removal_never_acts_on_a_repository_quarantined_again() {
        let (mut f, _) = removing();
        let old = f.record.qid;
        assert_eq!(f.remove(old), Removal::Removed);
        // Cloned again, with local work, and quarantined again: the first
        // removal, delivered late, touches none of it.
        std::fs::create_dir_all(f.storage.join(f.rid.canonical())).unwrap();
        std::fs::write(f.storage.join(f.rid.canonical()).join("HEAD"), b"x").unwrap();
        f.policies.seed(&f.rid, Scope::All).unwrap();
        let new = f
            .quarantine
            .quarantine(f.rid, Kind::Cache, "cache", None, "", LocalTime::now())
            .unwrap();
        assert_ne!(new.qid, old);
        assert_eq!(f.remove(old), Removal::NotQuarantined);
        assert!(f.storage.join(f.rid.canonical()).join("HEAD").exists());
        assert!(f.policies.is_seeding(&f.rid).unwrap());
        assert_eq!(f.quarantine.get(&f.rid).unwrap(), Some(new));
    }

    #[test]
    fn a_removal_cut_off_at_any_step_completes_when_run_again() {
        // Cut off after each of its first three steps: done by hand here.
        for done in 1..=3 {
            let (mut f, neighbour) = removing();
            if done >= 1 {
                f.policies.unseed(&f.rid).unwrap();
            }
            if done >= 2 {
                std::fs::remove_dir_all(f.storage.join(f.rid.canonical())).unwrap();
            }
            if done >= 3 {
                cob::cache::Remove::<cob::issue::Issue>::remove_all(&mut f.cache, &f.rid).unwrap();
                cob::cache::Remove::<cob::patch::Patch>::remove_all(&mut f.cache, &f.rid).unwrap();
            }
            assert_eq!(f.quarantine.get(&f.rid).unwrap(), Some(f.record.clone()));
            assert_eq!(f.remove(f.record.qid), Removal::Removed, "after {done}");
            assert!(f.gone(&f.rid), "after {done}");
            assert!(f.intact(&neighbour));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_removal_follows_no_link() {
        use std::os::unix::fs::symlink;

        let (mut f, _) = removing();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("kept"), b"x").unwrap();
        // The repository's directory holds a link to elsewhere.
        symlink(
            outside.path(),
            f.storage.join(f.rid.canonical()).join("link"),
        )
        .unwrap();
        assert_eq!(f.remove(f.record.qid), Removal::Removed);
        assert!(f.gone(&f.rid));
        assert!(outside.path().join("kept").exists());

        // A link in the repository's own place is removed itself.
        let (mut f, _) = removing();
        let name = f.storage.join(f.rid.canonical());
        std::fs::remove_dir_all(&name).unwrap();
        symlink(outside.path(), &name).unwrap();
        assert_eq!(f.remove(f.record.qid), Removal::Removed);
        assert!(std::fs::symlink_metadata(&name).is_err());
        assert!(outside.path().join("kept").exists());
    }

    // Review of heartwood #8, round 1: the process's own generator has no
    // part in a record's ID. Seeded alike just before each record, it gives
    // two records two IDs.
    #[test]
    fn two_records_never_share_a_qid_whatever_the_process_s_generator() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = Quarantine::open(tmp.path().join(QUARANTINE_DB_FILE)).unwrap();
        let (a, b) = (rid(), rid());
        let since = LocalTime::now();
        fastrand::seed(0x5eed);
        let first = db
            .quarantine(a, Kind::Cache, "cache", None, "", since)
            .unwrap();
        fastrand::seed(0x5eed);
        let second = db
            .quarantine(b, Kind::Cache, "cache", None, "", since)
            .unwrap();
        assert_ne!(first.qid, second.qid);
    }

    // Review of heartwood #8, round 1: a new record's ID that another record
    // holds is refused, and nothing is recorded or replaced.
    #[test]
    fn a_qid_another_record_holds_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = Quarantine::open(tmp.path().join(QUARANTINE_DB_FILE)).unwrap();
        let (a, b) = (rid(), rid());
        NEXT_QID.set(Some(7));
        let first = db
            .quarantine(a, Kind::Cache, "cache", None, "", LocalTime::now())
            .unwrap();
        assert_eq!(first.qid, Qid(7));
        NEXT_QID.set(Some(7));
        assert!(matches!(
            db.quarantine(b, Kind::Cache, "cache", None, "", LocalTime::now()),
            Err(Error::Collision(Qid(7)))
        ));
        assert_eq!(db.get(&b).unwrap(), None);
        assert_eq!(db.get(&a).unwrap(), Some(first));
        // Drawn from the operating system, IDs differ.
        let second = db
            .quarantine(b, Kind::Cache, "cache", None, "", LocalTime::now())
            .unwrap();
        assert_ne!(second.qid, Qid(7));
    }

    // Review of heartwood #8, round 1: the record stays until the deletion of
    // the repository's directory is on disk.
    #[test]
    fn a_removal_keeps_its_record_until_the_storage_directory_is_flushed() {
        let (mut f, neighbour) = removing();
        FAIL_SYNC.set(true);
        let result = remove_repo(
            &mut f.quarantine,
            &mut f.policies,
            &f.storage,
            &mut f.cache,
            f.rid,
            f.record.qid,
        );
        FAIL_SYNC.set(false);
        assert!(matches!(result, Err(RemoveError::Io(_))), "{result:?}");
        assert_eq!(f.quarantine.get(&f.rid).unwrap(), Some(f.record.clone()));
        assert_eq!(cache_rows(&f.cache, &f.rid), 2);
        // Run again, it completes.
        assert_eq!(f.remove(f.record.qid), Removal::Removed);
        assert!(f.gone(&f.rid));
        assert!(f.intact(&neighbour));
    }

    /// A junction at `link` to the directory `target`, as `mklink /J` makes
    /// one, with no privilege.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J {}", link.display());
    }

    // Review of heartwood #8, round 1: a junction in the repository's place is
    // removed itself, on Windows, and its target is left.
    #[cfg(windows)]
    #[test]
    fn a_junction_in_the_repository_s_place_is_removed_itself() {
        let (mut f, neighbour) = removing();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("kept"), b"x").unwrap();
        let name = f.storage.join(f.rid.canonical());
        std::fs::remove_dir_all(&name).unwrap();
        junction(&name, outside.path());
        assert_eq!(f.remove(f.record.qid), Removal::Removed);
        assert!(std::fs::symlink_metadata(&name).is_err());
        assert!(outside.path().join("kept").exists());
        assert!(f.quarantine.get(&f.rid).unwrap().is_none());
        assert!(f.intact(&neighbour));
    }
}
