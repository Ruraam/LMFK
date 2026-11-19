use lmfk_abi::{
    ABI_ANY_MINOR, ABI_V1, VersionRange, abi_major, abi_minor, is_compatible, make_version,
};

#[test]
fn version_encoding_is_stable() {
    assert_eq!(ABI_V1, 0x0001_0000);
    assert_eq!(make_version(1, 0), ABI_V1);
    assert_eq!(make_version(2, 7), 0x0002_0007);
    assert_eq!(abi_major(0x0002_0007), 2);
    assert_eq!(abi_minor(0x0002_0007), 7);
    assert_eq!(ABI_ANY_MINOR, 0xffff);
}

#[test]
fn v1_range_accepts_every_minor_of_major_one() {
    let range = VersionRange::v1();
    assert!(range.accepts(make_version(1, 0)));
    assert!(range.accepts(make_version(1, 7)));
    assert!(range.accepts(make_version(1, ABI_ANY_MINOR)));
}

#[test]
fn v1_range_rejects_other_majors() {
    let range = VersionRange::v1();
    assert!(!range.accepts(make_version(0, 9)));
    assert!(!range.accepts(make_version(2, 0)));
    assert!(!range.accepts(make_version(u16::MAX, 0)));
}

#[test]
fn bounded_range_checks_minor_edges() {
    let range = VersionRange::new(make_version(1, 3), make_version(2, 2));
    assert!(!range.accepts(make_version(1, 2)));
    assert!(range.accepts(make_version(1, 3)));
    assert!(range.accepts(make_version(1, ABI_ANY_MINOR)));
    assert!(range.accepts(make_version(2, 0)));
    assert!(range.accepts(make_version(2, 2)));
    assert!(!range.accepts(make_version(2, 3)));
    assert!(!range.accepts(make_version(3, 0)));
}

#[test]
fn helper_matches_range() {
    assert!(is_compatible(
        ABI_V1,
        make_version(1, ABI_ANY_MINOR),
        make_version(1, 5)
    ));
    assert!(!is_compatible(
        ABI_V1,
        make_version(1, ABI_ANY_MINOR),
        make_version(2, 0)
    ));
}
