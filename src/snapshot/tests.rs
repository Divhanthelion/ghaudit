//! Extraction of hostile archives, and the check against the commit's tree.

use super::*;
use std::process::Command;

/// Append one member with a raw, unchecked name, as a hostile archive could.
fn raw(b: &mut tar::Builder<Vec<u8>>, kind: tar::EntryType, name: &[u8], data: &[u8]) {
    raw_link(b, kind, name, data, None);
}

fn raw_link(
    b: &mut tar::Builder<Vec<u8>>,
    kind: tar::EntryType,
    name: &[u8],
    data: &[u8],
    link: Option<&[u8]>,
) {
    let mut h = tar::Header::new_gnu();
    let field = &mut h.as_old_mut().name;
    field.fill(0);
    field[..name.len()].copy_from_slice(name);
    h.set_entry_type(kind);
    h.set_size(data.len() as u64);
    h.set_mode(0o4755); // setuid and executable: must not survive
    if let Some(l) = link {
        h.set_link_name_literal(l).unwrap();
    }
    h.set_cksum();
    b.append(&h, data).unwrap();
}

/// A member whose name is longer than the 100-byte header field: a GNU long-name
/// member first, then the member itself.
fn long_name(b: &mut tar::Builder<Vec<u8>>, name: &[u8], data: &[u8]) {
    let mut long = name.to_vec();
    long.push(0);
    raw(b, tar::EntryType::GNULongName, b"././@LongLink", &long);
    raw(b, tar::EntryType::Regular, &name[..99], data);
}

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body_len = 1 + key.len() + 1 + value.len() + 1; // " key=value\n"
    let mut len = body_len + 1;
    while len.to_string().len() + body_len != len {
        len += 1;
    }
    let mut r = format!("{len} {key}=").into_bytes();
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

fn gz(tar: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(tar).unwrap();
    e.finish().unwrap()
}

/// An archive that starts like GitHub's: the commit in a pax global header, then the
/// top-level directory.
fn builder() -> tar::Builder<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    let comment = pax_record("comment", "a1b2".repeat(10).as_bytes());
    raw(
        &mut b,
        tar::EntryType::XGlobalHeader,
        b"pax_global_header",
        &comment,
    );
    raw(&mut b, tar::EntryType::Directory, b"o-r-abc/", b"");
    b
}

fn run_with(
    tar: Vec<u8>,
    opts: &ExtractOptions,
) -> (tempfile::TempDir, Result<Extracted, ExtractError>) {
    let outer = tempfile::tempdir().unwrap();
    let dest = outer.path().join("tree");
    fs::create_dir(&dest).unwrap();
    let r = extract_tar_gz(&gz(&tar)[..], &dest, opts, &AtomicBool::new(false));
    (outer, r)
}

fn run(b: tar::Builder<Vec<u8>>) -> (tempfile::TempDir, Extracted) {
    let (outer, r) = run_with(b.into_inner().unwrap(), &ExtractOptions::default());
    (outer, r.unwrap())
}

/// Every file under `root`, relative and `/`-separated. Fails on a symbolic link.
fn listing(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let t = e.file_type().unwrap();
            assert!(
                !t.is_symlink(),
                "a symbolic link was created: {:?}",
                e.path()
            );
            if t.is_dir() {
                walk(&e.path(), out);
            } else {
                out.push(e.path());
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut v: Vec<String> = files
        .iter()
        .map(|p| {
            p.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    v.sort();
    v
}

fn reasons(x: &Extracted) -> Vec<String> {
    x.skipped.iter().map(|(p, w)| format!("{p}: {w}")).collect()
}

#[test]
fn nothing_is_written_outside_the_destination() {
    let mut b = builder();
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/ok.txt", b"ok");
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/../escape.txt",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/a/../../escape2.txt",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc//double.txt",
        b"x",
    );
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/./dot.txt", b"x");
    long_name(
        &mut b,
        format!("o-r-abc/{}/../../../long-escape.txt", "d".repeat(100)).as_bytes(),
        b"x",
    );
    // A pax `path` record that climbs out.
    let rec = pax_record("path", b"o-r-abc/../../pax-escape.txt");
    raw(&mut b, tar::EntryType::XHeader, b"o-r-abc/PaxHeader", &rec);
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/innocent.txt",
        b"x",
    );
    // A pax `path` record that names an absolute path.
    let rec = pax_record("path", b"/etc/cron.d/pax-absolute");
    raw(&mut b, tar::EntryType::XHeader, b"o-r-abc/PaxHeader", &rec);
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/innocent2.txt",
        b"x",
    );
    let tar = b.into_inner().unwrap();
    let (outer, r) = run_with(tar, &ExtractOptions::default());
    // The absolute pax path is outside the top-level directory: the whole archive is
    // refused. Nothing was written outside `tree/` before that.
    assert!(matches!(r, Err(ExtractError::Malformed(_))), "{r:?}");
    assert!(
        listing(outer.path()).iter().all(|p| p.starts_with("tree/")),
        "{:?}",
        listing(outer.path())
    );

    let mut b = builder();
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/ok.txt", b"ok");
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/../escape.txt",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/a/../../escape2.txt",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc//double.txt",
        b"x",
    );
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/./dot.txt", b"x");
    long_name(
        &mut b,
        format!("o-r-abc/{}/../../../long-escape.txt", "d".repeat(100)).as_bytes(),
        b"x",
    );
    let rec = pax_record("path", b"o-r-abc/../../pax-escape.txt");
    raw(&mut b, tar::EntryType::XHeader, b"o-r-abc/PaxHeader", &rec);
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/innocent.txt",
        b"x",
    );
    let (outer, x) = run(b);
    assert_eq!(listing(outer.path()), vec!["tree/ok.txt"]);
    assert_eq!(x.files.keys().collect::<Vec<_>>(), vec!["ok.txt"]);
    assert_eq!(x.skipped.len(), 6, "{:#?}", reasons(&x));
    assert!(
        x.skipped
            .iter()
            .any(|(p, w)| p == "../../pax-escape.txt" && w.contains("..")),
        "the pax path replaces the header's name: {:#?}",
        reasons(&x)
    );
    assert_eq!(x.commit.as_deref(), Some("a1b2".repeat(10).as_str()));
}

#[test]
fn members_outside_the_top_level_directory_fail_the_extraction() {
    let mut b = builder();
    raw(&mut b, tar::EntryType::Regular, b"other-dir/x.txt", b"x");
    let (_o, r) = run_with(b.into_inner().unwrap(), &ExtractOptions::default());
    assert!(matches!(r, Err(ExtractError::Malformed(_))), "{r:?}");

    for first in [&b"/etc/cron.d/x"[..], b"../x", b"./x", b"x.txt"] {
        let mut b = tar::Builder::new(Vec::new());
        raw(&mut b, tar::EntryType::Regular, first, b"x");
        let (o, r) = run_with(b.into_inner().unwrap(), &ExtractOptions::default());
        assert!(matches!(r, Err(ExtractError::Malformed(_))), "{r:?}");
        assert!(listing(o.path()).is_empty());
    }
}

#[test]
fn links_become_plain_files_and_are_never_followed() {
    let mut b = builder();
    raw_link(
        &mut b,
        tar::EntryType::Symlink,
        b"o-r-abc/link",
        b"",
        Some(b"../../.."),
    );
    // A file "through" the link: never written into what the link names.
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/link/x", b"x");
    raw_link(
        &mut b,
        tar::EntryType::Symlink,
        b"o-r-abc/abs",
        b"",
        Some(b"/etc/passwd"),
    );
    raw_link(
        &mut b,
        tar::EntryType::Link,
        b"o-r-abc/hard",
        b"",
        Some(b"o-r-abc/abs"),
    );
    raw(&mut b, tar::EntryType::Char, b"o-r-abc/tty", b"");
    raw(&mut b, tar::EntryType::Block, b"o-r-abc/disk", b"");
    raw(&mut b, tar::EntryType::Fifo, b"o-r-abc/fifo", b"");
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/ok.txt", b"ok");
    let (outer, x) = run(b);
    let tree = outer.path().join("tree");
    assert_eq!(listing(&tree), vec!["abs", "link", "ok.txt"]);
    assert_eq!(fs::read(tree.join("link")).unwrap(), b"../../..");
    assert_eq!(fs::read(tree.join("abs")).unwrap(), b"/etc/passwd");
    assert_eq!(x.files["link"], git_blob_sha1(b"../../.."));
    let why: BTreeMap<&str, &str> = x
        .skipped
        .iter()
        .map(|(p, w)| (p.as_str(), w.as_str()))
        .collect();
    assert!(why["link/x"].starts_with("cannot be written"), "{why:?}");
    assert_eq!(why["hard"], "hard link in the archive");
    assert_eq!(why["tty"], "character device in the archive");
    assert_eq!(why["disk"], "block device in the archive");
    assert_eq!(why["fifo"], "named pipe in the archive");
    assert_eq!(why.len(), 5, "{why:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(tree.join("ok.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7111, 0, "no setuid or executable bits");
    }
}

#[test]
fn sparse_members_are_skipped() {
    let mut b = builder();
    // A GNU sparse file of 8 bytes, of which 4 (at offset 4) are stored.
    let mut h = tar::Header::new_gnu();
    h.as_old_mut().name[..14].copy_from_slice(b"o-r-abc/sparse");
    h.set_entry_type(tar::EntryType::GNUSparse);
    h.set_size(4);
    h.set_mode(0o644);
    let gnu = h.as_gnu_mut().unwrap();
    gnu.set_real_size(8);
    gnu.sparse[0].set_offset(4);
    gnu.sparse[0].set_length(4);
    h.set_cksum();
    b.append(&h, &b"data"[..]).unwrap();
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/ok.txt", b"ok");
    let (outer, r) = run_with(b.into_inner().unwrap(), &ExtractOptions::default());
    // Listed as skipped, never written.
    match r {
        Ok(x) => assert_eq!(
            x.skipped,
            vec![(
                "sparse".to_string(),
                "sparse file in the archive".to_string()
            )]
        ),
        Err(e) => panic!("{e:?}"),
    }
    assert!(!outer.path().join("tree/sparse").exists());
}

#[test]
fn names_this_system_cannot_store_are_listed() {
    let mut b = builder();
    for name in [
        "CON", "aux.txt", "a\\b.txt", "col:on", "trail. ", "README", "Readme",
    ] {
        raw(
            &mut b,
            tar::EntryType::Regular,
            format!("o-r-abc/{name}").as_bytes(),
            name.as_bytes(),
        );
    }
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/caf\xe9.txt",
        b"latin-1 name",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/.git/config",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/sub/.GIT/hooks",
        b"x",
    );
    long_name(
        &mut b,
        format!("o-r-abc/{}", "n".repeat(256)).as_bytes(),
        b"x",
    );
    let deep = format!("o-r-abc/{}x", "d/".repeat(2100));
    long_name(&mut b, deep.as_bytes(), b"x");
    let (outer, x) = run(b);
    let skipped: Vec<&str> = x.skipped.iter().map(|(p, _)| p.as_str()).collect();
    assert!(skipped.contains(&".git/config"), "{skipped:?}");
    assert!(skipped.contains(&"sub/.GIT/hooks"), "{skipped:?}");
    assert!(
        skipped.iter().any(|p| p.len() == 256),
        "long name: {skipped:?}"
    );
    assert!(
        skipped.iter().any(|p| p.len() > 4096),
        "long path: {skipped:?}"
    );
    if cfg!(windows) {
        for name in ["CON", "aux.txt", "a\\b.txt", "col:on", "trail. ", "Readme"] {
            assert!(skipped.contains(&name), "{name} not listed: {skipped:?}");
        }
        assert!(skipped.iter().any(|p| p.starts_with("caf")), "not UTF-8");
        assert_eq!(
            fs::read(outer.path().join("tree/README")).unwrap(),
            b"README"
        );
    } else if cfg!(target_os = "macos") {
        assert!(skipped.contains(&"Readme"), "{skipped:?}");
    } else {
        // Linux and Android keep every name git allows.
        assert_eq!(skipped.len(), 4, "{:#?}", reasons(&x));
        assert_eq!(x.files.len(), 8);
    }
}

#[test]
fn decompression_bombs_and_entry_floods_are_bounded() {
    let mut b = builder();
    let zeros = vec![0u8; 8 << 20];
    for i in 0..8 {
        raw(
            &mut b,
            tar::EntryType::Regular,
            format!("o-r-abc/z{i}").as_bytes(),
            &zeros,
        );
    }
    let tar = b.into_inner().unwrap();
    let unpacked = ExtractOptions {
        max_unpacked_bytes: 16 << 20,
        ..ExtractOptions::default()
    };
    let (_o, r) = run_with(tar.clone(), &unpacked);
    assert!(matches!(r, Err(ExtractError::Limit(_))), "{r:?}");
    let stored = ExtractOptions {
        max_stored_bytes: 20 << 20,
        ..ExtractOptions::default()
    };
    let (_o, r) = run_with(tar.clone(), &stored);
    assert!(matches!(r, Err(ExtractError::Limit(_))), "{r:?}");
    // Over max_file_size: listed, not written, and extraction goes on.
    let small = ExtractOptions {
        max_file_size: Some(1 << 20),
        ..ExtractOptions::default()
    };
    let (outer, r) = run_with(tar, &small);
    let x = r.unwrap();
    assert_eq!(x.too_large.len(), 8);
    assert_eq!(x.too_large[0], ("z0".to_string(), 8 << 20));
    assert!(x.files.is_empty());
    assert_eq!(x.stored_bytes, 0);
    assert!(listing(outer.path()).is_empty());

    let mut b = builder();
    for i in 0..50 {
        raw(
            &mut b,
            tar::EntryType::Regular,
            format!("o-r-abc/f{i}").as_bytes(),
            b"",
        );
    }
    let few = ExtractOptions {
        max_entries: 10,
        ..ExtractOptions::default()
    };
    let (_o, r) = run_with(b.into_inner().unwrap(), &few);
    assert!(matches!(r, Err(ExtractError::Limit(_))), "{r:?}");
}

#[test]
fn a_truncated_download_is_an_error_not_a_smaller_archive() {
    let mut b = builder();
    for i in 0..20 {
        let data = format!("file {i}\n").repeat(200);
        raw(
            &mut b,
            tar::EntryType::Regular,
            format!("o-r-abc/f{i}.txt").as_bytes(),
            data.as_bytes(),
        );
    }
    let full = gz(&b.into_inner().unwrap());
    let mut accepted = Vec::new();
    for cut in (1..full.len()).step_by(7).chain([full.len() - 1]) {
        let outer = tempfile::tempdir().unwrap();
        let r = extract_tar_gz(
            &full[..cut],
            outer.path(),
            &ExtractOptions::default(),
            &AtomicBool::new(false),
        );
        if r.is_ok() {
            accepted.push(cut);
        }
    }
    assert!(accepted.is_empty(), "accepted cuts: {accepted:?}");
    let outer = tempfile::tempdir().unwrap();
    let x = extract_tar_gz(
        &full[..],
        outer.path(),
        &ExtractOptions::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(x.files.len(), 20);

    // A corrupted byte in the gzip trailer (the CRC) is caught as well.
    let mut bad = full.clone();
    let at = bad.len() - 6;
    bad[at] ^= 0xff;
    let outer = tempfile::tempdir().unwrap();
    let r = extract_tar_gz(
        &bad[..],
        outer.path(),
        &ExtractOptions::default(),
        &AtomicBool::new(false),
    );
    assert!(r.is_err());
}

#[test]
fn excluded_paths_are_not_written() {
    let mut b = builder();
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/src/app.py", b"x");
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/node_modules/p/i.js",
        b"x",
    );
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/docs/guide.md",
        b"x",
    );
    let outer = tempfile::tempdir().unwrap();
    let filter = PathFilter::new(outer.path(), &["docs/".into()]).unwrap();
    let opts = ExtractOptions {
        filter: Some(&filter),
        ..ExtractOptions::default()
    };
    let (outer, r) = run_with(b.into_inner().unwrap(), &opts);
    let x = r.unwrap();
    assert_eq!(listing(&outer.path().join("tree")), vec!["src/app.py"]);
    assert!(x.skipped.is_empty(), "excluded paths are not listed");
}

#[test]
fn cancelling_stops_the_extraction() {
    let mut b = builder();
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/a.txt", b"x");
    let outer = tempfile::tempdir().unwrap();
    let r = extract_tar_gz(
        &gz(&b.into_inner().unwrap())[..],
        outer.path(),
        &ExtractOptions::default(),
        &AtomicBool::new(true),
    );
    assert!(matches!(r, Err(ExtractError::Cancelled)), "{r:?}");
    assert!(listing(outer.path()).is_empty());
}

#[test]
fn git_blob_ids() {
    assert_eq!(
        git_blob_sha1(b""),
        "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    );
    assert_eq!(
        git_blob_sha1(b"hello\n"),
        "ce013625030ba8dba906f756967f9e9ca394464a"
    );
    // The writer computes the same id while it writes.
    let mut b = builder();
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/h.txt",
        b"hello\n",
    );
    raw(&mut b, tar::EntryType::Regular, b"o-r-abc/empty", b"");
    let (_o, x) = run(b);
    assert_eq!(x.files["h.txt"], "ce013625030ba8dba906f756967f9e9ca394464a");
    assert_eq!(x.files["empty"], "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    assert_eq!(x.stored_bytes, 6);
}

fn entry(path: &str, mode: &str, kind: &str, sha: &str) -> TreeEntry {
    TreeEntry {
        path: path.into(),
        mode: mode.into(),
        kind: kind.into(),
        sha: sha.into(),
        size: Some(1),
    }
}

#[test]
fn reconcile_finds_missing_changed_and_unexpected_files() {
    let hello = git_blob_sha1(b"hello\n");
    let target = git_blob_sha1(b"../outside");
    let stored: BTreeMap<String, String> = [
        ("same.txt", hello.as_str()),
        ("subst.txt", hello.as_str()),
        ("link", target.as_str()),
        ("extra.txt", hello.as_str()),
    ]
    .iter()
    .map(|(p, s)| (p.to_string(), s.to_string()))
    .collect();
    let tree = vec![
        entry("same.txt", "100644", "blob", &hello),
        entry(
            "subst.txt",
            "100644",
            "blob",
            &git_blob_sha1(b"$Format:%H$\n"),
        ),
        entry("link", "120000", "blob", &target),
        entry(".github/workflows/ci.yml", "100644", "blob", &hello),
        entry(".github", "040000", "tree", &hello),
        entry("vendor/lib", "160000", "commit", &hello),
        entry("node_modules/x/i.js", "100644", "blob", &hello),
    ];
    let r = reconcile(&stored, &tree, None);
    let paths = |v: &[TreeEntry]| v.iter().map(|e| e.path.clone()).collect::<Vec<_>>();
    assert_eq!(
        paths(&r.missing),
        vec![".github/workflows/ci.yml", "node_modules/x/i.js"]
    );
    assert_eq!(paths(&r.changed), vec!["subst.txt"]);
    assert_eq!(r.unexpected, vec!["extra.txt"]);
    assert!(!r.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let filter = PathFilter::new(dir.path(), &[".github/".into()]).unwrap();
    let r = reconcile(&stored, &tree, Some(&filter));
    assert!(
        r.missing.is_empty(),
        "filtered paths are not missing: {r:?}"
    );
}

fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .args(["-c", "core.autocrlf=false", "-c", "core.eol=lf"])
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// The real thing: `git archive` of a repository that uses every attribute that
/// changes an archive, checked against `git ls-tree`.
#[test]
fn a_git_archive_is_checked_against_the_commit() {
    let repo = tempfile::tempdir().unwrap();
    let dir = repo.path();
    if git(dir, &["init", "-q"]).is_none() {
        return; // git not installed
    }
    let files = [
        (
            ".gitattributes",
            "/.github/ export-ignore\nhidden.env export-ignore\nsubst.txt export-subst\nident.txt ident\ncrlf.txt text eol=crlf\n",
        ),
        (
            ".github/workflows/ci.yml",
            "on: pull_request_target\njobs: {}\n",
        ),
        ("hidden.env", "PASSWORD=value\n"),
        ("subst.txt", "commit $Format:%H$\n"),
        ("ident.txt", "$Id$\n"),
        ("crlf.txt", "a\nb\n"),
        ("src/normal.txt", "hello\n"),
    ];
    for (path, content) in files {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    assert!(git(dir, &["add", "-A"]).is_some());
    // A symbolic link, added to the index directly so this works on any system.
    let mut hash = Command::new("git")
        .args(["hash-object", "-w", "--stdin"])
        .current_dir(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    hash.stdin
        .take()
        .unwrap()
        .write_all(b"../../../etc/passwd")
        .unwrap();
    let link_blob = String::from_utf8(hash.wait_with_output().unwrap().stdout).unwrap();
    let cacheinfo = format!("120000,{},evil-link", link_blob.trim());
    assert!(git(dir, &["update-index", "--add", "--cacheinfo", &cacheinfo]).is_some());
    assert!(git(dir, &["commit", "-q", "--no-gpg-sign", "-m", "init"]).is_some());
    let head = String::from_utf8(git(dir, &["rev-parse", "HEAD"]).unwrap()).unwrap();
    let head = head.trim();
    let prefix = format!("--prefix=o-r-{}/", &head[..7]);
    let tar = git(dir, &["archive", "--format=tar", &prefix, "HEAD"]).unwrap();

    let outer = tempfile::tempdir().unwrap();
    let x = extract_tar_gz(
        &gz(&tar)[..],
        outer.path(),
        &ExtractOptions::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        x.commit.as_deref(),
        Some(head),
        "the pax comment names the commit"
    );
    assert!(x.skipped.is_empty(), "{:#?}", reasons(&x));
    assert_eq!(
        fs::read(outer.path().join("evil-link")).unwrap(),
        b"../../../etc/passwd"
    );
    assert!(!outer.path().join(".github").exists(), "export-ignore");
    assert!(!outer.path().join("hidden.env").exists(), "export-ignore");

    let ls = String::from_utf8(git(dir, &["ls-tree", "-r", "-l", "HEAD"]).unwrap()).unwrap();
    let tree: Vec<TreeEntry> = ls
        .lines()
        .map(|line| {
            let (meta, path) = line.split_once('\t').unwrap();
            let f: Vec<&str> = meta.split_whitespace().collect();
            TreeEntry {
                path: path.into(),
                mode: f[0].into(),
                kind: f[1].into(),
                sha: f[2].into(),
                size: f[3].parse().ok(),
            }
        })
        .collect();
    let r = reconcile(&x.files, &tree, None);
    let paths = |v: &[TreeEntry]| v.iter().map(|e| e.path.clone()).collect::<Vec<_>>();
    assert_eq!(
        paths(&r.missing),
        vec![".github/workflows/ci.yml", "hidden.env"]
    );
    assert_eq!(
        paths(&r.changed),
        vec!["crlf.txt", "ident.txt", "subst.txt"]
    );
    assert!(r.unexpected.is_empty(), "{r:?}");
}
