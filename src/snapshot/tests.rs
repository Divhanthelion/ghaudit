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
    // A long path is listed, shortened.
    let (long, why) = x
        .skipped
        .iter()
        .find(|(_, why)| why.starts_with("path longer"))
        .expect("long path listed");
    assert_eq!(long.chars().count(), 201, "{why}");
    assert!(long.starts_with("d/d/") && long.ends_with('…'), "{long}");
    // A name that is not UTF-8 could only be listed under another name.
    assert!(
        x.skipped
            .iter()
            .any(|(p, why)| p.starts_with("caf") && why.contains("UTF-8")),
        "{skipped:?}"
    );
    if cfg!(windows) {
        for name in ["CON", "aux.txt", "a\\b.txt", "col:on", "trail. ", "Readme"] {
            assert!(skipped.contains(&name), "{name} not listed: {skipped:?}");
        }
        assert_eq!(
            fs::read(outer.path().join("tree/README")).unwrap(),
            b"README"
        );
    } else if cfg!(target_os = "macos") {
        assert!(skipped.contains(&"Readme"), "{skipped:?}");
    } else {
        // Linux and Android keep every other name git allows.
        assert_eq!(skipped.len(), 5, "{:#?}", reasons(&x));
        assert_eq!(x.files.len(), 7);
    }
}

/// On Windows and macOS a name can lead to another entry: another case, or on Windows
/// an 8.3 alias (`TERRAF~1` for `.terraform`). Nothing is written through one, so a
/// file never lands, unlisted, in a directory the scan skips: what is on disk is
/// exactly what is recorded, and everything else is listed.
#[test]
fn names_that_lead_to_another_entry_are_listed() {
    let members = [
        (".terraform/main.tf", "a"),
        ("TERRAF~1/hidden.tf", "b"),
        ("node_modules/p/i.js", "c"),
        ("Node_Modules/p/evil.js", "d"),
        ("docs/guide.md", "e"),
        ("DOCS", "f"),
        ("readme.md", "g"),
        ("README.MD/x", "h"),
    ];
    let mut b = builder();
    for (name, data) in members {
        raw(
            &mut b,
            tar::EntryType::Regular,
            format!("o-r-abc/{name}").as_bytes(),
            data.as_bytes(),
        );
    }
    let (outer, x) = run(b);
    let recorded: Vec<String> = x.files.keys().cloned().collect();
    assert_eq!(listing(&outer.path().join("tree")), recorded);
    assert_eq!(
        x.files.len() + x.skipped.len(),
        members.len(),
        "{:#?}",
        reasons(&x)
    );
    if cfg!(any(windows, target_os = "macos")) {
        let skipped: Vec<&str> = x.skipped.iter().map(|(p, _)| p.as_str()).collect();
        for name in ["Node_Modules/p/evil.js", "DOCS", "README.MD/x"] {
            assert!(skipped.contains(&name), "{name}: {:#?}", reasons(&x));
        }
    }

    // A file fetched afterwards follows the same rules, in the directories the
    // extraction created.
    let tree = outer.path().join("tree");
    let mut writer = Writer::resume(&tree, 1 << 20, x.stored_bytes, x.dirs);
    let cancel = AtomicBool::new(false);
    let mut write = |rel: &str| writer.write(rel.as_bytes(), &mut &b"z"[..], 1, &cancel);
    assert!(
        write("docs/new.md").unwrap().is_ok(),
        "an existing directory"
    );
    let again = write("Node_Modules/p/later.js").unwrap();
    if cfg!(any(windows, target_os = "macos")) {
        assert!(again.is_err(), "{again:?}");
    }
    let recorded: Vec<String> = x.files.keys().cloned().collect();
    let on_disk = listing(&tree);
    assert!(
        on_disk
            .iter()
            .all(|p| recorded.contains(p) || p == "docs/new.md" || p == "Node_Modules/p/later.js"),
        "{on_disk:?}"
    );
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

/// A path within 4096 bytes can still be over this system's limit once under the
/// destination (about 1 KiB on macOS, 4 KiB on Linux and Android): it is listed, and
/// the extraction goes on.
#[test]
fn a_path_too_long_for_the_file_system_is_listed() {
    let deep = format!("{}x", format!("{}/", "d".repeat(250)).repeat(16));
    assert!(deep.len() <= MAX_PATH_BYTES);
    let mut b = builder();
    long_name(&mut b, format!("o-r-abc/{deep}").as_bytes(), b"deep");
    raw(
        &mut b,
        tar::EntryType::Regular,
        b"o-r-abc/after.txt",
        b"after",
    );
    let (outer, x) = run(b);
    assert!(x.files.contains_key("after.txt"), "{:#?}", reasons(&x));
    assert_eq!(x.files.len() + x.skipped.len(), 2, "{:#?}", reasons(&x));
    if let Some((_, why)) = x.skipped.first() {
        assert_eq!(why, PATH_TOO_LONG_HERE);
    }
    assert!(outer.path().join("tree/after.txt").exists());
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

// Fetching through the GitHub API, against a mock server.

/// A commit id for the tests.
pub(crate) const SHA: &str = "5e7a1c0de5e7a1c0de5e7a1c0de5e7a1c0de5e7a";

/// GitHub's archive of a commit with these files: the commit in a pax global header,
/// then everything under `acme-app-5e7a1c0/`.
pub(crate) fn github_archive(commit: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let files: Vec<(&[u8], &[u8])> = files.iter().map(|(p, d)| (p.as_bytes(), *d)).collect();
    github_archive_raw(commit, &files)
}

/// [`github_archive`], with names as raw bytes, of any length.
fn github_archive_raw(commit: &str, files: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let comment = pax_record("comment", commit.as_bytes());
    raw(
        &mut b,
        tar::EntryType::XGlobalHeader,
        b"pax_global_header",
        &comment,
    );
    raw(&mut b, tar::EntryType::Directory, b"acme-app-5e7a1c0/", b"");
    for (path, data) in files {
        let mut name = b"acme-app-5e7a1c0/".to_vec();
        name.extend_from_slice(path);
        if name.len() < 100 {
            raw(&mut b, tar::EntryType::Regular, &name, data);
        } else {
            long_name(&mut b, &name, data);
        }
    }
    gz(&b.into_inner().unwrap())
}

/// The tree GitHub lists for a commit with these files.
pub(crate) fn tree_json(files: &[(&str, &[u8])], truncated: bool) -> String {
    let entries: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, data)| {
            serde_json::json!({
                "path": path, "mode": "100644", "type": "blob",
                "sha": git_blob_sha1(data), "size": data.len(),
            })
        })
        .collect();
    serde_json::json!({ "sha": SHA, "tree": entries, "truncated": truncated }).to_string()
}

/// Serve `acme/app` at [`SHA`]: its archive (through a redirect, as GitHub does), its
/// tree and the given blobs. `None` for the archive: an empty repository.
pub(crate) async fn serve_repo(
    archive: Option<Vec<u8>>,
    tree: String,
    blobs: Vec<Vec<u8>>,
) -> (String, crate::github::mock::Log) {
    let blobs = blobs
        .into_iter()
        .map(|data| (git_blob_sha1(&data), data))
        .collect();
    serve_repo_with(archive, tree, blobs).await
}

/// [`serve_repo`], with blobs by the id they are served under.
async fn serve_repo_with(
    archive: Option<Vec<u8>>,
    tree: String,
    blobs: BTreeMap<String, Vec<u8>>,
) -> (String, crate::github::mock::Log) {
    crate::github::mock::serve_bytes(move |line| {
        let json = |status, body: &str| (status, vec![], body.as_bytes().to_vec());
        let path = line.trim_start_matches("GET ");
        if path == "/repos/acme/app" {
            json(
                200,
                r#"{"full_name":"acme/app","clone_url":"x","default_branch":"main"}"#,
            )
        } else if path == "/repos/acme/app/commits/heads/main" {
            match archive {
                Some(_) => json(200, SHA),
                None => json(409, r#"{"message":"Git Repository is empty."}"#),
            }
        } else if path.starts_with("/repos/acme/app/tarball/") {
            let to = format!("/codeload/acme/app/legacy.tar.gz/{SHA}");
            (302, vec![("location", to)], Vec::new())
        } else if path.starts_with("/codeload/") {
            (200, vec![], archive.clone().unwrap_or_default())
        } else if path.starts_with(&format!("/repos/acme/app/git/trees/{SHA}")) {
            json(200, &tree)
        } else if let Some(blob) = path.strip_prefix("/repos/acme/app/git/blobs/")
            && let Some(data) = blobs.get(blob)
        {
            (200, vec![], data.clone())
        } else {
            json(404, r#"{"message":"Not Found"}"#)
        }
    })
    .await
}

fn fetch_options() -> FetchOptions {
    FetchOptions {
        limits: Limits::default(),
        max_file_size: 1000,
        exclude: Vec::new(),
        write_all: false,
    }
}

async fn fetch_app(api: &str, opts: &FetchOptions) -> crate::Result<Snapshot> {
    let gh = GitHub::new(api, None).unwrap();
    fetch(&gh, "acme", "app", None, opts).await
}

#[tokio::test]
async fn fetching_checks_every_file_against_the_commit() {
    let workflow: &[u8] = b"on: pull_request_target\n";
    let big = vec![b'x'; 2000];
    // The commit's files...
    let commit: Vec<(&str, &[u8])> = vec![
        (
            ".gitattributes",
            b"/.github/ export-ignore\nsubst.txt export-subst\n",
        ),
        (".github/workflows/ci.yml", workflow),
        ("subst.txt", b"$Format:%H$\n"),
        ("app.py", b"print(1)\n"),
        ("big.bin", &big),
        ("node_modules/x/index.js", b"x\n"),
    ];
    // ...and the archive GitHub makes of them: .github left out, subst.txt changed,
    // plus a file that is not in the commit.
    let archived: Vec<(&str, &[u8])> = vec![
        (".gitattributes", commit[0].1),
        ("subst.txt", b"5e7a1c0de\n"),
        ("app.py", b"print(1)\n"),
        ("big.bin", &big),
        ("node_modules/x/index.js", b"x\n"),
        ("extra.txt", b"not in the commit\n"),
    ];
    let (api, log) = serve_repo(
        Some(github_archive(SHA, &archived)),
        tree_json(&commit, false),
        vec![workflow.to_vec(), commit[2].1.to_vec()],
    )
    .await;
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    assert_eq!(snapshot.commit.as_deref(), Some(SHA));
    assert_eq!(snapshot.incomplete, None);
    let root = snapshot.path.clone();
    assert_eq!(
        listing(&root),
        vec![
            ".gitattributes",
            ".github/workflows/ci.yml",
            "app.py",
            "subst.txt"
        ],
        "node_modules is excluded, big.bin too large, extra.txt removed"
    );
    assert_eq!(
        fs::read(root.join(".github/workflows/ci.yml")).unwrap(),
        workflow
    );
    assert_eq!(fs::read(root.join("subst.txt")).unwrap(), b"$Format:%H$\n");
    assert_eq!(snapshot.too_large, vec![("big.bin".to_string(), 2000)]);
    assert_eq!(snapshot.skipped.len(), 1, "{:?}", snapshot.skipped);
    assert_eq!(snapshot.skipped[0].0, "extra.txt");
    assert!(
        !snapshot._dir.path().join("archive.tar.gz").exists(),
        "the archive is deleted"
    );
    let log = log.lock().unwrap().clone();
    assert_eq!(
        log.iter().filter(|l| l.contains("/git/blobs/")).count(),
        2,
        "one request per file to fetch: {log:?}"
    );

    // Everything is deleted with the snapshot.
    let dir = snapshot._dir.path().to_path_buf();
    drop(snapshot);
    assert!(!dir.exists());

    // With dependency checks, every file is written: osv-scanner reads lockfiles of any
    // size, anywhere.
    let all = FetchOptions {
        write_all: true,
        ..fetch_options()
    };
    let snapshot = fetch_app(&api, &all).await.unwrap();
    assert!(snapshot.path.join("node_modules/x/index.js").exists());
    assert!(snapshot.path.join("big.bin").exists());
    assert!(snapshot.too_large.is_empty());
}

#[tokio::test]
async fn what_cannot_be_confirmed_is_reported() {
    let files: Vec<(&str, &[u8])> = vec![("a.txt", b"a\n"), ("b.txt", b"b\n"), ("c.txt", b"c\n")];
    let archive = github_archive(SHA, &files[..1]);

    // A truncated tree. The files it does not list stay: they may be the commit's.
    let (api, _) = serve_repo(
        Some(github_archive(SHA, &files)),
        tree_json(&files[..1], true),
        vec![],
    )
    .await;
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    let why = snapshot.incomplete.clone().unwrap();
    assert!(
        why.starts_with(UNCONFIRMED) && why.contains("truncated"),
        "{why}"
    );
    assert_eq!(listing(&snapshot.path), vec!["a.txt", "b.txt", "c.txt"]);
    assert!(snapshot.skipped.is_empty(), "{:?}", snapshot.skipped);

    // More files left out of the archive than are fetched one by one.
    let blobs = vec![b"b\n".to_vec(), b"c\n".to_vec()];
    let (api, log) = serve_repo(Some(archive.clone()), tree_json(&files, false), blobs).await;
    let mut opts = fetch_options();
    opts.limits.max_backfill_files = 1;
    let snapshot = fetch_app(&api, &opts).await.unwrap();
    let why = snapshot.incomplete.unwrap();
    assert!(
        why.starts_with(UNCONFIRMED) && why.contains("1 more files"),
        "{why}"
    );
    assert_eq!(snapshot.skipped.len(), 1, "the file not fetched is listed");
    let fetched = log
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("/git/blobs/"))
        .count();
    assert_eq!(fetched, 1);

    // An archive of another commit, or of no named commit.
    let other = github_archive(&"0".repeat(40), &files[..1]);
    let (api, _) = serve_repo(Some(other), tree_json(&files[..1], false), vec![]).await;
    let err = fetch_app(&api, &fetch_options())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(UNCONFIRMED) && err.contains("not 5e7a"),
        "{err}"
    );
    let unnamed = github_archive("not a commit id", &files[..1]);
    let (api, _) = serve_repo(Some(unnamed), tree_json(&files[..1], false), vec![]).await;
    let err = fetch_app(&api, &fetch_options())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not name its commit"), "{err}");

    // A download cut short.
    let mut cut = archive.clone();
    cut.truncate(cut.len() - 10);
    let (api, _) = serve_repo(Some(cut), tree_json(&files[..1], false), vec![]).await;
    let err = fetch_app(&api, &fetch_options())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains(UNCONFIRMED), "{err}");

    // A file whose content does not match the id it was fetched by.
    let tampered = BTreeMap::from([(git_blob_sha1(b"b\n"), b"tampered\n".to_vec())]);
    let (api, _) = serve_repo_with(
        Some(archive.clone()),
        tree_json(&files[..2], false),
        tampered,
    )
    .await;
    let err = fetch_app(&api, &fetch_options())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match its id"), "{err}");
}

/// Dependency checks need every file, whatever its size: a large lockfile the archive
/// leaves out is fetched, and one over the limits leaves the snapshot unconfirmed
/// rather than quietly missing.
#[tokio::test]
async fn dependency_checks_get_large_files_too() {
    let lock = vec![b'l'; 2000]; // over max_file_size
    let commit: Vec<(&str, &[u8])> = vec![
        (".gitattributes", b"Cargo.lock export-ignore\n"),
        ("Cargo.lock", &lock),
    ];
    let (api, _) = serve_repo(
        Some(github_archive(SHA, &commit[..1])),
        tree_json(&commit, false),
        vec![lock.clone()],
    )
    .await;
    let all = FetchOptions {
        write_all: true,
        ..fetch_options()
    };
    let snapshot = fetch_app(&api, &all).await.unwrap();
    assert_eq!(snapshot.incomplete, None);
    assert_eq!(fs::read(snapshot.path.join("Cargo.lock")).unwrap(), lock);
    assert!(snapshot.too_large.is_empty());

    // Without dependency checks it is too large, as discovery would say.
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    assert_eq!(snapshot.too_large, vec![("Cargo.lock".to_string(), 2000)]);
    assert!(!snapshot.path.join("Cargo.lock").exists());

    // Over the bytes fetched one by one.
    let mut tight = all.clone();
    tight.limits.max_backfill_bytes = 1000;
    let snapshot = fetch_app(&api, &tight).await.unwrap();
    let why = snapshot.incomplete.unwrap();
    assert!(why.starts_with(UNCONFIRMED), "{why}");
    assert!(
        snapshot.skipped.iter().any(|(p, _)| p == "Cargo.lock"),
        "{:?}",
        snapshot.skipped
    );
}

/// What could not be written is listed under its exact path only. A lossy name (not
/// UTF-8) or a shortened one (too long) could be another file's, and must not stop that
/// file from being fetched.
#[tokio::test]
async fn files_listed_under_another_name_are_still_fetched() {
    // `ci\u{FFFD}.yml` is a real file, changed in the archive (line endings); beside it
    // is a name that is not UTF-8 and reads the same once decoded lossily.
    let real = "ci\u{FFFD}.yml";
    let commit: Vec<(&str, &[u8])> = vec![(real, b"on: push\n")];
    let long = format!("{}x", "d/".repeat(2100));
    let archived: Vec<(&[u8], &[u8])> = vec![
        (real.as_bytes(), b"on: push\r\n"),
        (b"ci\xff.yml", b"other"),
        (long.as_bytes(), b"x"),
    ];
    let mut tree = commit.clone();
    tree.push((&long, b"x"));
    let (api, log) = serve_repo(
        Some(github_archive_raw(SHA, &archived)),
        tree_json(&tree, false),
        vec![commit[0].1.to_vec()],
    )
    .await;
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    assert_eq!(fs::read(snapshot.path.join(real)).unwrap(), b"on: push\n");
    assert_eq!(snapshot.incomplete, None);
    // The long path is listed once, shortened, and not fetched.
    let long_listed: Vec<&(String, String)> = snapshot
        .skipped
        .iter()
        .filter(|(p, _)| p.starts_with("d/d/"))
        .collect();
    assert_eq!(long_listed.len(), 1, "{:?}", snapshot.skipped);
    assert!(long_listed[0].0.ends_with('…'));
    let fetched = log
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("/git/blobs/"))
        .count();
    assert_eq!(fetched, 1, "only the changed file");
}

/// Two names that are not UTF-8 can reach the API as one lossy path.
#[tokio::test]
async fn a_path_listed_twice_is_not_confirmed() {
    let files: Vec<(&str, &[u8])> = vec![("a\u{FFFD}.txt", b"a\n"), ("a\u{FFFD}.txt", b"b\n")];
    let (api, _) = serve_repo(
        Some(github_archive(SHA, &files[..1])),
        tree_json(&files, false),
        vec![b"b\n".to_vec()],
    )
    .await;
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    let why = snapshot.incomplete.unwrap();
    assert!(why.contains("paths twice"), "{why}");
}

#[tokio::test]
async fn an_empty_repository_has_no_files_and_no_commit() {
    let (api, log) = serve_repo(None, tree_json(&[], false), vec![]).await;
    let snapshot = fetch_app(&api, &fetch_options()).await.unwrap();
    assert_eq!(snapshot.commit, None);
    assert!(listing(&snapshot.path).is_empty());
    assert!(
        !log.lock().unwrap().iter().any(|l| l.contains("tarball")),
        "nothing to download"
    );
}
