//! A repository's files without git: GitHub's archive of one commit, checked file by
//! file against the commit's tree.
//!
//! GitHub builds its archives with `git archive`, which honors `.gitattributes`: files
//! marked `export-ignore` are left out, and `export-subst`, `ident` and `eol` change
//! file contents. A repository could use that to hide files from a scan of its archive.
//! So every file written here has its git blob id computed while it is written, and
//! [`reconcile`] compares those ids with the commit's tree: whatever is missing or
//! different is then fetched on its own.
//!
//! The archive is untrusted input. [`extract_tar_gz`] never uses tar's own unpacking.
//! It writes regular files only, with names it validated, under one destination
//! directory, and never creates a symbolic link: a link becomes a plain file holding
//! its target, as `git clone -c core.symlinks=false` checks it out. Hard links, devices
//! and other special members are skipped and listed. Sizes and counts are capped, and
//! the gzip stream is read to its end so that a download cut short is an error rather
//! than a smaller archive.

use crate::discovery::PathFilter;
use crate::error::Error;
use crate::github::{GitHub, TreeEntry};
use futures::StreamExt;
// Git names blobs by their SHA-1, so the check against the commit's tree has to use it.
// GitHub rejects objects that carry a SHA-1 collision attack, and an archive's file
// would have to collide with the committed blob it was made from.
// ghaudit:ignore[rust/weak-hash]
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;
use tracing::debug;

#[cfg(test)]
pub(crate) mod tests;

/// The start of every reason a fetch gives for not vouching for its files.
pub const UNCONFIRMED: &str = "could not confirm the download is complete";

/// Limits for [`fetch`].
#[derive(Debug, Clone)]
pub struct Limits {
    /// Size of the downloaded `.tar.gz`.
    pub max_download_bytes: u64,
    /// Bytes out of the gzip decoder.
    pub max_unpacked_bytes: u64,
    /// Bytes written to disk.
    pub max_stored_bytes: u64,
    /// Archive members.
    pub max_entries: usize,
    /// Files fetched one by one because the archive lacks them or changed them.
    pub max_backfill_files: usize,
    /// Their total size.
    pub max_backfill_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_download_bytes: 1 << 30,
            max_unpacked_bytes: 4 << 30,
            max_stored_bytes: 2 << 30,
            max_entries: 300_000,
            max_backfill_files: 300,
            max_backfill_bytes: 20 << 20,
        }
    }
}

/// What [`fetch`] writes.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub limits: Limits,
    /// Files larger than this are listed in `too_large`, and never fetched one by one.
    pub max_file_size: u64,
    /// `--exclude` patterns.
    pub exclude: Vec<String>,
    /// Write every file of the archive, whatever its size or path, for osv-scanner,
    /// which reads lockfiles in directories and of sizes discovery skips. Otherwise
    /// excluded paths and files over `max_file_size` are not written at all.
    pub write_all: bool,
}

/// A commit's files in a temporary directory, which is deleted when this is dropped.
#[derive(Debug)]
pub struct Snapshot {
    _dir: TempDir,
    pub path: PathBuf,
    /// `None` for an empty repository.
    pub commit: Option<String>,
    /// `(path, reason)` of the commit's files that were not written, other than those
    /// in `too_large`.
    pub skipped: Vec<(String, String)>,
    /// `(path, size)` of files over `max_file_size` that were not written.
    pub too_large: Vec<(String, u64)>,
    /// Set (starting with [`UNCONFIRMED`]) when the files could not all be checked
    /// against the commit: the file analyzers' results then cannot be vouched for.
    pub incomplete: Option<String>,
}

/// Sets the flag when dropped, so the blocking extraction of a dropped fetch stops.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Fetch the files of `owner/name` at the tip of its default branch (`branch`, when
/// the caller knows it), without git:
///
/// 1. resolve the branch to a commit id;
/// 2. download GitHub's archive of that commit;
/// 3. extract it with [`extract_tar_gz`] on a blocking thread, then delete it;
/// 4. require the archive's pax comment to name that commit;
/// 5. fetch the commit's tree and [`reconcile`] the files with it;
/// 6. fetch files that are missing or different one by one, within
///    `max_backfill_files` and `max_backfill_bytes`, and remove unexpected ones.
///
/// Every file of the commit that is not written is listed with a reason. A truncated
/// tree, or more files to fetch than the limits allow, sets `incomplete`.
pub async fn fetch(
    gh: &GitHub,
    owner: &str,
    name: &str,
    branch: Option<&str>,
    opts: &FetchOptions,
) -> crate::Result<Snapshot> {
    let dir = crate::git::work_dir()?;
    let path = dir.path().join("repo");
    fs::create_dir(&path)?;
    let snapshot = Snapshot {
        _dir: dir,
        path,
        commit: None,
        skipped: Vec::new(),
        too_large: Vec::new(),
        incomplete: None,
    };
    let Some(sha) = gh.default_branch_head(owner, name, branch).await? else {
        return Ok(snapshot); // an empty repository, as git clones it
    };
    let limits = &opts.limits;
    let archive = snapshot._dir.path().join("archive.tar.gz");
    let bytes = gh
        .download_archive(owner, name, &sha, &archive, limits.max_download_bytes)
        .await?;
    debug!("downloaded {bytes} bytes for {owner}/{name}@{sha}");

    // The temporary directory moves into the blocking task and back, so that if this
    // future is dropped, it is deleted only once the extraction has stopped.
    let cancel = Arc::new(AtomicBool::new(false));
    let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
    let (extracted, mut snapshot) = {
        let opts = opts.clone();
        let cancel = Arc::clone(&cancel);
        tokio::task::spawn_blocking(move || {
            let extracted = extract_file(&archive, &snapshot.path, &opts, &cancel);
            let removed = fs::remove_file(&archive);
            (
                extracted.and_then(|x| removed.map(|()| x).map_err(Into::into)),
                snapshot,
            )
        })
        .await
        .map_err(|e| Error::Archive(format!("extraction crashed: {e}")))?
    };
    let extracted = extracted?;
    match &extracted.commit {
        Some(commit) if *commit == sha => {}
        Some(other) => {
            return Err(Error::Archive(format!(
                "{UNCONFIRMED}: the archive is of commit {other}, not {sha}"
            )));
        }
        None => {
            return Err(Error::Archive(format!(
                "{UNCONFIRMED}: the archive does not name its commit"
            )));
        }
    }
    snapshot.commit = Some(sha.clone());

    let tree = gh.tree(owner, name, &sha).await?;
    let filter = filter(&snapshot.path, opts)?;
    let check = reconcile(&extracted.files, &tree.entries, filter.as_ref());
    let mut incomplete = Vec::new();
    if tree.truncated {
        incomplete.push("GitHub's list of the commit's files is truncated".to_string());
    }
    for path in &check.unexpected {
        // Not part of the commit: the scan must not report on it.
        fs::remove_file(snapshot.path.join(path))?;
        snapshot.skipped.push((
            path.clone(),
            "in GitHub's archive but not in the commit: removed".into(),
        ));
    }

    // Files written with other content than the commit's go; the commit's version is
    // fetched instead. Files the extraction could not write (names this system does not
    // allow) would fail again: they stay listed with their reason.
    let unwritable: HashSet<&str> = extracted.skipped.iter().map(|(p, _)| p.as_str()).collect();
    for entry in &check.changed {
        fs::remove_file(snapshot.path.join(&entry.path))?;
    }
    let mut wanted = Vec::new();
    for entry in check.changed.iter().chain(&check.missing) {
        if unwritable.contains(entry.path.as_str()) {
            continue;
        }
        let size = entry.size.unwrap_or(0);
        if size > opts.max_file_size {
            snapshot.too_large.push((entry.path.clone(), size));
        } else {
            wanted.push(entry.clone());
        }
    }
    snapshot.skipped.extend(extracted.skipped.iter().cloned());

    let mut budget = limits.max_backfill_bytes;
    let mut fetch_now = Vec::new();
    let mut over = 0;
    for entry in wanted {
        let size = entry.size.unwrap_or(0);
        if fetch_now.len() < limits.max_backfill_files && size <= budget {
            budget -= size;
            fetch_now.push(entry);
        } else {
            over += 1;
            snapshot.skipped.push((
                entry.path,
                "differs from GitHub's archive, over the limit of files fetched one by one".into(),
            ));
        }
    }
    if over > 0 {
        incomplete.push(format!(
            "{over} more files differ from GitHub's archive than are fetched one by one \
             ({} files, {} MiB)",
            limits.max_backfill_files,
            limits.max_backfill_bytes >> 20
        ));
    }
    // Names still on disk, for the writer's same-name check.
    let removed: HashSet<&str> = check
        .changed
        .iter()
        .map(|e| e.path.as_str())
        .chain(check.unexpected.iter().map(String::as_str))
        .collect();
    let kept: Vec<String> = extracted
        .files
        .keys()
        .filter(|p| !removed.contains(p.as_str()))
        .cloned()
        .collect();
    let stored_bytes = extracted.stored_bytes;

    let contents: Vec<(TreeEntry, Vec<u8>)> = futures::stream::iter(fetch_now)
        .map(|entry| async move {
            let content = gh
                .blob_raw(owner, name, &entry.sha, opts.max_file_size)
                .await?;
            if !git_blob_sha1(&content).eq_ignore_ascii_case(&entry.sha) {
                return Err(Error::Archive(format!(
                    "{UNCONFIRMED}: {} does not match its id",
                    entry.path
                )));
            }
            Ok((entry, content))
        })
        .buffer_unordered(4)
        .collect::<Vec<crate::Result<_>>>()
        .await
        .into_iter()
        .collect::<crate::Result<_>>()?;
    debug!(
        "fetched {} files of {owner}/{name} one by one",
        contents.len()
    );

    let (written, mut snapshot) = {
        let max_stored = limits.max_stored_bytes;
        let cancel = Arc::clone(&cancel);
        tokio::task::spawn_blocking(move || {
            let mut writer = Writer::resume(&snapshot.path, max_stored, stored_bytes, &kept);
            let mut skipped = Vec::new();
            for (entry, content) in contents {
                let result = writer.write(
                    entry.path.as_bytes(),
                    &entry.path,
                    &mut &content[..],
                    content.len() as u64,
                    &cancel,
                );
                match result {
                    Ok(Ok(_)) => {}
                    Ok(Err(why)) => skipped.push((entry.path, why)),
                    Err(e) => return (Err(e), snapshot),
                }
            }
            (Ok(skipped), snapshot)
        })
        .await
        .map_err(|e| Error::Archive(format!("writing files crashed: {e}")))?
    };
    snapshot
        .skipped
        .extend(written.map_err(|e| Error::Archive(e.to_string()))?);
    snapshot.skipped.sort();
    snapshot.too_large.sort();
    if !incomplete.is_empty() {
        snapshot.incomplete = Some(format!("{UNCONFIRMED}: {}", incomplete.join("; ")));
    }
    Ok(snapshot)
}

fn filter(root: &Path, opts: &FetchOptions) -> crate::Result<Option<PathFilter>> {
    if opts.write_all {
        return Ok(None);
    }
    PathFilter::new(root, &opts.exclude).map(Some)
}

fn extract_file(
    archive: &Path,
    dest: &Path,
    opts: &FetchOptions,
    cancel: &AtomicBool,
) -> crate::Result<Extracted> {
    let file = io::BufReader::new(fs::File::open(archive)?);
    let filter = filter(dest, opts)?;
    let extract = ExtractOptions {
        max_unpacked_bytes: opts.limits.max_unpacked_bytes,
        max_stored_bytes: opts.limits.max_stored_bytes,
        max_entries: opts.limits.max_entries,
        max_file_size: (!opts.write_all).then_some(opts.max_file_size),
        filter: filter.as_ref(),
    };
    extract_tar_gz(file, dest, &extract, cancel).map_err(|e| match e {
        ExtractError::Io(e) => Error::Archive(format!("{UNCONFIRMED}: {e}")),
        e => Error::Archive(e.to_string()),
    })
}

/// Limits for [`extract_tar_gz`].
#[derive(Clone)]
pub struct ExtractOptions<'a> {
    /// Bytes out of the gzip decoder: tar headers, file data, and data not written.
    pub max_unpacked_bytes: u64,
    /// Bytes written to disk.
    pub max_stored_bytes: u64,
    /// Archive members of any type.
    pub max_entries: usize,
    /// Larger files are listed in `too_large` instead of written; `None` writes them.
    pub max_file_size: Option<u64>,
    /// Paths this filter drops (excluded directories, `--exclude`) are not written.
    pub filter: Option<&'a PathFilter>,
}

impl Default for ExtractOptions<'_> {
    fn default() -> Self {
        Self {
            max_unpacked_bytes: 4 << 30,
            max_stored_bytes: 2 << 30,
            max_entries: 300_000,
            max_file_size: None,
            filter: None,
        }
    }
}

/// What [`extract_tar_gz`] wrote.
#[derive(Debug, Default)]
pub struct Extracted {
    /// The commit id `git archive` put in the pax global header (`comment`).
    pub commit: Option<String>,
    /// Relative `/`-separated path of each file written, with the git blob id of what
    /// was written.
    pub files: BTreeMap<String, String>,
    /// `(path, size)` of files over `max_file_size`, not written.
    pub too_large: Vec<(String, u64)>,
    /// `(path, reason)` of members that were not written for any other reason.
    pub skipped: Vec<(String, String)>,
    pub stored_bytes: u64,
}

#[derive(Debug)]
pub enum ExtractError {
    Io(io::Error),
    /// A size or count limit was reached.
    Limit(String),
    /// The archive does not have the shape `git archive` gives it.
    Malformed(String),
    Cancelled,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::Io(e) => write!(f, "could not read the archive: {e}"),
            ExtractError::Limit(why) => write!(f, "{why}"),
            ExtractError::Malformed(why) => write!(f, "unexpected archive: {why}"),
            ExtractError::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<io::Error> for ExtractError {
    fn from(e: io::Error) -> Self {
        // `Capped` reports its limit as an io::Error; tar passes it through.
        if let Some(limit) = e.get_ref().and_then(|i| i.downcast_ref::<LimitReached>()) {
            return ExtractError::Limit(limit.0.clone());
        }
        ExtractError::Io(e)
    }
}

#[derive(Debug)]
struct LimitReached(String);

impl std::fmt::Display for LimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LimitReached {}

/// Counts the bytes read and fails past a limit, so a decompression bomb costs bounded
/// time.
struct Capped<R> {
    inner: R,
    read: u64,
    max: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        if self.read > self.max {
            return Err(io::Error::other(LimitReached(format!(
                "the archive expands to more than {} MiB",
                self.max >> 20
            ))));
        }
        Ok(n)
    }
}

/// Extract `git archive`'s `.tar.gz` output from `src` into the existing, empty
/// directory `dest`. See the module documentation for the rules.
///
/// Every member must sit under the archive's single top-level directory
/// (`owner-repo-sha/` for GitHub), which is stripped. Members that cannot be written
/// here (names this system does not allow, a second file whose name differs only in
/// case on Windows or macOS, special files) are listed in `skipped`; nothing is dropped
/// silently. Paths `opts.filter` drops are not listed: discovery would skip them too.
pub fn extract_tar_gz<R: Read>(
    src: R,
    dest: &Path,
    opts: &ExtractOptions,
    cancel: &AtomicBool,
) -> Result<Extracted, ExtractError> {
    let gz = flate2::read::GzDecoder::new(src);
    let mut archive = tar::Archive::new(Capped {
        inner: gz,
        read: 0,
        max: opts.max_unpacked_bytes,
    });
    let mut out = Extracted::default();
    let mut writer = Writer::new(dest, opts.max_stored_bytes);
    let mut prefix: Option<Vec<u8>> = None;

    for (count, entry) in archive.entries()?.enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(ExtractError::Cancelled);
        }
        if count >= opts.max_entries {
            return Err(ExtractError::Limit(format!(
                "the archive has more than {} entries",
                opts.max_entries
            )));
        }
        let mut entry = entry?;
        let kind = entry.header().entry_type();

        if kind.is_pax_global_extensions() {
            if let Some(extensions) = entry.pax_extensions()? {
                for ext in extensions.flatten() {
                    if ext.key() == Ok("comment") {
                        let value = ext.value().unwrap_or_default().trim().to_ascii_lowercase();
                        if crate::github::is_object_id(&value) {
                            out.commit = Some(value);
                        }
                    }
                }
            }
            continue;
        }

        // `path_bytes` applies GNU long names and pax `path` records.
        let raw = entry.path_bytes().into_owned();
        let Some(rel) = strip_prefix(&raw, &mut prefix, kind.is_dir()) else {
            return Err(ExtractError::Malformed(format!(
                "member outside the top-level directory: {:?}",
                String::from_utf8_lossy(&raw)
            )));
        };
        if rel.is_empty() || kind.is_dir() {
            continue; // directories are created as files need them
        }
        let rel_text = String::from_utf8_lossy(&rel).into_owned();
        if opts.filter.is_some_and(|f| !f.keeps(&rel_text)) {
            continue;
        }

        // Only regular files and symbolic links become files.
        let link_target: Option<Vec<u8>> = match kind {
            tar::EntryType::Regular | tar::EntryType::Continuous => None,
            tar::EntryType::Symlink => Some(
                entry
                    .link_name_bytes()
                    .map(|b| b.into_owned())
                    .unwrap_or_default(),
            ),
            other => {
                out.skipped
                    .push((rel_text, format!("{} in the archive", member_kind(other))));
                continue;
            }
        };
        // tar applies a pax `size` record to `size()` (since 0.4.45).
        let size = link_target
            .as_ref()
            .map_or_else(|| entry.size(), |t| t.len() as u64);
        if opts.max_file_size.is_some_and(|max| size > max) {
            out.too_large.push((rel_text, size));
            continue; // tar skips the unread data
        }
        let written = match link_target {
            Some(target) => writer.write(&rel, &rel_text, &mut &target[..], size, cancel)?,
            None => writer.write(&rel, &rel_text, &mut entry, size, cancel)?,
        };
        match written {
            Ok(id) => {
                out.files.insert(rel_text, id);
            }
            Err(why) => out.skipped.push((rel_text, why)),
        }
    }
    // tar stops at its end-of-archive marker. Read the gzip stream to its end as well,
    // so its CRC and length check the whole download: a connection cut at a member
    // boundary would otherwise look like a smaller, valid archive.
    io::copy(&mut archive.into_inner(), &mut io::sink())?;
    out.stored_bytes = writer.stored_bytes;
    Ok(out)
}

fn member_kind(kind: tar::EntryType) -> &'static str {
    match kind {
        tar::EntryType::Link => "hard link",
        tar::EntryType::Char => "character device",
        tar::EntryType::Block => "block device",
        tar::EntryType::Fifo => "named pipe",
        tar::EntryType::GNUSparse => "sparse file",
        _ => "unsupported member type",
    }
}

/// Writes files under `dest`, never over an existing path, and counts what it stored.
/// Shared by extraction and by the files fetched afterwards, so both follow one set of
/// rules (and one set of names, for case-insensitive file systems).
pub(crate) struct Writer<'a> {
    dest: &'a Path,
    /// Names written so far, lower-cased where the file system ignores case.
    taken: HashSet<String>,
    stored_bytes: u64,
    max_stored_bytes: u64,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(dest: &'a Path, max_stored_bytes: u64) -> Self {
        Self {
            dest,
            taken: HashSet::new(),
            stored_bytes: 0,
            max_stored_bytes,
        }
    }

    /// Go on writing into a directory that holds `names`, `stored_bytes` in all.
    fn resume(dest: &'a Path, max_stored_bytes: u64, stored_bytes: u64, names: &[String]) -> Self {
        let mut writer = Self::new(dest, max_stored_bytes);
        writer.stored_bytes = stored_bytes;
        writer.taken = names.iter().map(|p| name_key(p)).collect();
        writer
    }

    /// Write `size` bytes from `src` to `rel` (relative, `/`-separated, as raw bytes;
    /// `text` is it for messages). Returns the git blob id of what was written, or why
    /// the file cannot be written here. `Err` only for failures that end the extraction.
    pub(crate) fn write(
        &mut self,
        rel: &[u8],
        text: &str,
        src: &mut dyn Read,
        size: u64,
        cancel: &AtomicBool,
    ) -> Result<Result<String, String>, ExtractError> {
        let rel_path = match validate(rel) {
            Ok(p) => p,
            Err(why) => return Ok(Err(why)),
        };
        if self.stored_bytes + size > self.max_stored_bytes {
            return Err(ExtractError::Limit(format!(
                "the files take more than {} MiB",
                self.max_stored_bytes >> 20
            )));
        }
        let key = name_key(text);
        if self.taken.contains(&key) {
            return Ok(Err(SAME_NAME.into()));
        }
        let target = self.dest.join(&rel_path);
        if let Some(parent) = target.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            // A link stored as the file "a", then "a/b": a parent is a file.
            if is_name_conflict(&e) {
                return Ok(Err(format!("cannot be written: {e}")));
            }
            return Err(e.into());
        }
        // Safe from links: nothing under `dest` is one, because none is ever created.
        // `create_new` never reuses an existing path either.
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Ok(Err(SAME_NAME.into()));
            }
            Err(e) if is_name_conflict(&e) => {
                return Ok(Err(format!("cannot be written: {e}")));
            }
            Err(e) => return Err(e.into()),
        };
        self.taken.insert(key);
        let mut hasher = Sha1::new();
        hasher.update(format!("blob {size}\0").as_bytes());
        let mut src = src.take(size);
        let mut buf = vec![0u8; 64 * 1024];
        let mut written = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(ExtractError::Cancelled);
            }
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
            written += n as u64;
        }
        if written != size {
            return Err(ExtractError::Malformed(format!(
                "{text}: {written} of {size} bytes"
            )));
        }
        self.stored_bytes += written;
        Ok(Ok(hex(&hasher.finalize())))
    }
}

const SAME_NAME: &str = "another file has the same name on this file system";

/// A path as this system compares names: Windows and macOS ignore case.
fn name_key(path: &str) -> String {
    if cfg!(any(windows, target_os = "macos")) {
        path.to_lowercase()
    } else {
        path.to_string()
    }
}

fn is_name_conflict(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
            | io::ErrorKind::NotFound
            | io::ErrorKind::AlreadyExists
    )
}

/// Strip the single top-level directory, which the first member names.
fn strip_prefix(raw: &[u8], prefix: &mut Option<Vec<u8>>, is_dir: bool) -> Option<Vec<u8>> {
    let trimmed = raw.strip_suffix(b"/").unwrap_or(raw);
    let (first, rest) = match trimmed.iter().position(|&b| b == b'/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (trimmed, &b""[..]),
    };
    if first.is_empty() || first == b"." || first == b".." {
        return None;
    }
    match prefix {
        Some(p) if p.as_slice() == first => Some(rest.to_vec()),
        Some(_) => None,
        None if is_dir && rest.is_empty() => {
            *prefix = Some(first.to_vec());
            Some(Vec::new())
        }
        None => None,
    }
}

/// Turn a path relative to the top-level directory into a relative path on this
/// system, or say why it cannot be one.
fn validate(rel: &[u8]) -> Result<PathBuf, String> {
    if rel.len() > 4096 {
        return Err("path longer than 4096 bytes".into());
    }
    let mut out = PathBuf::new();
    for comp in rel.split(|&b| b == b'/') {
        if comp.is_empty() {
            return Err("empty path component".into());
        }
        if comp == b"." || comp == b".." {
            return Err("path contains . or ..".into());
        }
        if comp.eq_ignore_ascii_case(b".git") {
            return Err("git does not allow a .git directory in a repository".into());
        }
        if comp.contains(&0) {
            return Err("path contains a NUL byte".into());
        }
        if comp.len() > 255 {
            return Err("file name longer than 255 bytes".into());
        }
        out.push(component(comp)?);
    }
    if out.as_os_str().is_empty() {
        return Err("empty path".into());
    }
    Ok(out)
}

#[cfg(unix)]
fn component(comp: &[u8]) -> Result<std::ffi::OsString, String> {
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::OsStr::from_bytes(comp).to_os_string())
}

#[cfg(not(unix))]
fn component(comp: &[u8]) -> Result<std::ffi::OsString, String> {
    let s = std::str::from_utf8(comp).map_err(|_| "name is not UTF-8".to_string())?;
    if cfg!(windows) {
        windows_name(s)?;
    }
    Ok(s.into())
}

/// Names Windows cannot store, or would store as another name.
#[cfg(not(unix))]
fn windows_name(s: &str) -> Result<(), String> {
    if s.chars()
        .any(|c| c < ' ' || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err("name has characters Windows does not allow".into());
    }
    if s.ends_with('.') || s.ends_with(' ') {
        return Err("name ends with a dot or space".into());
    }
    if s.eq_ignore_ascii_case("git~1") {
        return Err("git does not allow a .git directory in a repository".into());
    }
    let stem = s
        .split('.')
        .next()
        .unwrap_or(s)
        .trim_end()
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.chars().count() == 4
        && matches!(stem.chars().nth(3), Some('0'..='9' | '¹' | '²' | '³')));
    if reserved {
        return Err("name is reserved on Windows".into());
    }
    Ok(())
}

/// Git's id for a blob with this content: the SHA-1 of `blob <size>\0<content>`.
pub fn git_blob_sha1(content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How the files written differ from the commit's tree.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconcile {
    /// Files of the commit that were not written.
    pub missing: Vec<TreeEntry>,
    /// Files written with other content than the commit's (`export-subst`, `ident`,
    /// line endings, Git LFS content).
    pub changed: Vec<TreeEntry>,
    /// Files written that the commit does not have.
    pub unexpected: Vec<String>,
}

impl Reconcile {
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty() && self.unexpected.is_empty()
    }
}

/// Compare the files written (`path -> git blob id`) with the commit's tree. Only blobs
/// count (files and symbolic links, whose blob is the target); directories and
/// submodules, which a clone leaves empty, do not. Paths `filter` drops are ignored.
pub fn reconcile(
    stored: &BTreeMap<String, String>,
    tree: &[TreeEntry],
    filter: Option<&PathFilter>,
) -> Reconcile {
    let mut result = Reconcile::default();
    let mut in_tree: HashSet<&str> = HashSet::new();
    for entry in tree.iter().filter(|e| e.kind == "blob") {
        if filter.is_some_and(|f| !f.keeps(&entry.path)) {
            continue;
        }
        in_tree.insert(entry.path.as_str());
        match stored.get(&entry.path) {
            None => result.missing.push(entry.clone()),
            Some(id) if !id.eq_ignore_ascii_case(&entry.sha) => result.changed.push(entry.clone()),
            Some(_) => {}
        }
    }
    result.unexpected = stored
        .keys()
        .filter(|path| !in_tree.contains(path.as_str()))
        .cloned()
        .collect();
    result
}
