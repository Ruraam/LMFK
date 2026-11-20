//! Read-only parsing and correlation of Linux kernel module metadata.
//!
//! This crate deliberately performs no filesystem access. Callers provide
//! metadata contents read from the running kernel's module directory and
//! /proc/modules, making parsing deterministic and fixture-testable.

use std::collections::{BTreeMap, BTreeSet};

use lmfk_core::{MatchSource, Module, ModuleState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIssue {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleAlias {
    pub pattern: String,
    pub module: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleIndex {
    aliases: Vec<ModuleAlias>,
    builtin: BTreeSet<String>,
    present: BTreeSet<String>,
    dependencies: BTreeMap<String, Vec<String>>,
    loaded: BTreeSet<String>,
}

impl ModuleIndex {
    /// Parse the text form of modules.alias. Binary modules.alias.bin is not
    /// decoded here; callers may use the text index when the kernel provides it.
    pub fn parse_aliases(input: &str) -> (Vec<ModuleAlias>, Vec<ParseIssue>) {
        let mut aliases = Vec::new();
        let mut issues = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || fields[0] != "alias" {
                issues.push(ParseIssue {
                    line: index + 1,
                    message: "expected: alias <modalias-pattern> <module>".into(),
                });
                continue;
            }
            aliases.push(ModuleAlias {
                pattern: fields[1].to_owned(),
                module: normalize_module_name(fields[2]),
            });
        }
        (aliases, issues)
    }

    /// Parse modules.builtin paths and derive canonical module names.
    pub fn parse_builtin(input: &str) -> (BTreeSet<String>, Vec<ParseIssue>) {
        parse_module_paths(input)
    }

    /// Parse modules.dep. Dependency paths are reduced to canonical module names.
    pub fn parse_dependencies(input: &str) -> (BTreeMap<String, Vec<String>>, Vec<ParseIssue>) {
        let mut map = BTreeMap::new();
        let mut issues = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((module_path, deps)) = line.split_once(':') else {
                issues.push(ParseIssue {
                    line: index + 1,
                    message: "missing ':' separator in modules.dep entry".into(),
                });
                continue;
            };
            let decoded_module_path = decode_dep_path(module_path);
            let Some(module) = module_name_from_path(&decoded_module_path) else {
                issues.push(ParseIssue {
                    line: index + 1,
                    message: "invalid module path".into(),
                });
                continue;
            };
            let mut dependencies = Vec::new();
            let mut malformed = false;
            for encoded_path in deps.split_whitespace() {
                let path = decode_dep_path(encoded_path);
                match module_name_from_path(&path) {
                    Some(dependency) => dependencies.push(dependency),
                    None => {
                        issues.push(ParseIssue {
                            line: index + 1,
                            message: format!("invalid dependency module path: {encoded_path}"),
                        });
                        malformed = true;
                    }
                }
            }
            if !malformed {
                map.insert(module, dependencies);
            }
        }
        (map, issues)
    }

    /// Parse /proc/modules. The first whitespace-delimited column is the name.
    pub fn parse_loaded(input: &str) -> (BTreeSet<String>, Vec<ParseIssue>) {
        let mut loaded = BTreeSet::new();
        let mut issues = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            let valid_address = fields.get(5).is_some_and(|address| {
                *address == "0"
                    || address.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            });
            let valid_record = fields.len() == 6
                && !fields[0].is_empty()
                && fields[1].parse::<u64>().is_ok()
                && fields[2].parse::<u64>().is_ok()
                && (fields[3] == "-" || fields[3].split(',').all(|name| !name.is_empty()))
                && matches!(fields[4], "Live" | "Loading" | "Unloading")
                && valid_address;
            if !valid_record {
                issues.push(ParseIssue {
                    line: index + 1,
                    message: "invalid /proc/modules record (expected name, size, refcount, users, state, address)".into(),
                });
                continue;
            }
            loaded.insert(normalize_module_name(fields[0]));
        }
        (loaded, issues)
    }

    pub fn from_metadata(
        aliases: &str,
        builtin: &str,
        dependencies: &str,
        loaded: &str,
    ) -> (Self, Vec<ParseIssue>) {
        let (aliases, mut issues) = Self::parse_aliases(aliases);
        let (builtin, mut builtin_issues) = Self::parse_builtin(builtin);
        let (dependencies, mut dependency_issues) = Self::parse_dependencies(dependencies);
        let (loaded, mut loaded_issues) = Self::parse_loaded(loaded);
        issues.append(&mut builtin_issues);
        issues.append(&mut dependency_issues);
        issues.append(&mut loaded_issues);
        // This is the set indexed by text modules.dep, not a complete
        // filesystem inventory of every possible module file.
        let present = dependencies.keys().cloned().collect();
        (
            Self {
                aliases,
                builtin,
                present,
                dependencies,
                loaded,
            },
            issues,
        )
    }

    /// Return matching module candidates for a device modalias and optional
    /// bound-driver link. `Missing` means absent from the parsed text index,
    /// not proof that no compatible module exists on the host. No package
    /// inference or installation is attempted.
    pub fn resolve(&self, modalias: &str, bound_driver: Option<&str>) -> Vec<Module> {
        let mut candidates: BTreeMap<String, MatchSource> = BTreeMap::new();

        if !modalias.is_empty() {
            for alias in &self.aliases {
                if glob_match(&alias.pattern, modalias) {
                    candidates
                        .entry(alias.module.clone())
                        .or_insert(MatchSource::ModulesAlias);
                }
            }
        }

        if let Some(driver) = bound_driver.filter(|name| !name.trim().is_empty()) {
            candidates
                .entry(normalize_module_name(driver))
                .or_insert(MatchSource::DriverLink);
        }

        candidates
            .into_iter()
            .map(|(name, source)| {
                let state = if self.loaded.contains(&name) {
                    ModuleState::Loaded
                } else if self.builtin.contains(&name) {
                    ModuleState::Builtin
                } else if self.present.contains(&name) {
                    ModuleState::Available
                } else if source == MatchSource::DriverLink {
                    ModuleState::Unknown
                } else {
                    ModuleState::Missing
                };
                let dependencies = self.dependencies.get(&name).cloned().unwrap_or_default();
                Module {
                    name,
                    match_source: source,
                    state,
                    dependencies,
                    firmwares: Vec::new(),
                }
            })
            .collect()
    }

    /// Return a stable, de-duplicated transitive dependency list. Cycles are
    /// guarded against and the requested root module is excluded.
    pub fn dependency_closure(&self, module: &str) -> Vec<String> {
        let root = normalize_module_name(module);
        let mut visited = BTreeSet::new();
        let mut pending = self.dependencies.get(&root).cloned().unwrap_or_default();
        while let Some(name) = pending.pop() {
            if name == root || !visited.insert(name.clone()) {
                continue;
            }
            if let Some(children) = self.dependencies.get(&name) {
                pending.extend(children.iter().cloned());
            }
        }
        visited.into_iter().collect()
    }

    pub fn is_builtin(&self, module: &str) -> bool {
        self.builtin.contains(&normalize_module_name(module))
    }
    pub fn is_loaded(&self, module: &str) -> bool {
        self.loaded.contains(&normalize_module_name(module))
    }
    pub fn is_present(&self, module: &str) -> bool {
        self.present.contains(&normalize_module_name(module))
    }
}

fn parse_module_paths(input: &str) -> (BTreeSet<String>, Vec<ParseIssue>) {
    let mut names = BTreeSet::new();
    let mut issues = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let path = raw.trim();
        if path.is_empty() || path.starts_with('#') {
            continue;
        }
        match module_name_from_path(path) {
            Some(name) => {
                names.insert(name);
            }
            None => issues.push(ParseIssue {
                line: index + 1,
                message: "invalid module path".into(),
            }),
        }
    }
    (names, issues)
}

fn module_name_from_path(path: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    let uncompressed = [".xz", ".zst", ".gz"]
        .iter()
        .find_map(|suffix| file.strip_suffix(suffix))
        .unwrap_or(file);
    let stem = uncompressed.strip_suffix(".ko")?;
    if stem.is_empty() || stem == "." || stem == ".." {
        return None;
    }
    Some(normalize_module_name(stem))
}

/// Decode escaped whitespace and backslashes emitted in modules.dep.
/// Unknown escapes are preserved so malformed paths are reported, not guessed.
fn decode_dep_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() && bytes[index + 1] == b'x' {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 2..index + 4]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    if matches!(value, b' ' | b'\t' | b'\\') {
                        decoded.push(value);
                        index += 4;
                        continue;
                    }
                }
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

pub fn normalize_module_name(name: &str) -> String {
    name.trim().replace('-', "_")
}

/// Match the wildcard syntax used by modules.alias: '*', '?', and bracket
/// character classes. Matching is byte-oriented because modaliases are ASCII.
fn glob_match(pattern: &str, value: &str) -> bool {
    fn class_match(class: &[u8], byte: u8) -> bool {
        let mut i = 0;
        while i < class.len() {
            if i + 2 < class.len() && class[i + 1] == b'-' {
                if (class[i]..=class[i + 2]).contains(&byte) {
                    return true;
                }
                i += 3;
            } else {
                if class[i] == byte {
                    return true;
                }
                i += 1;
            }
        }
        false
    }
    fn visit(
        p: &[u8],
        v: &[u8],
        pi: usize,
        vi: usize,
        memo: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(pi, vi)) {
            return *result;
        }
        let result = if pi == p.len() {
            vi == v.len()
        } else {
            match p[pi] {
                b'*' => {
                    visit(p, v, pi + 1, vi, memo) || (vi < v.len() && visit(p, v, pi, vi + 1, memo))
                }
                b'?' => vi < v.len() && visit(p, v, pi + 1, vi + 1, memo),
                b'[' => {
                    let close = p[pi + 1..]
                        .iter()
                        .position(|b| *b == b']')
                        .map(|n| pi + 1 + n);
                    if let Some(end) = close.filter(|end| *end > pi + 1) {
                        if vi >= v.len() {
                            false
                        } else {
                            let mut class = &p[pi + 1..end];
                            let negated = class.first().is_some_and(|b| *b == b'!' || *b == b'^');
                            if negated {
                                class = &class[1..];
                            }
                            class_match(class, v[vi]) != negated
                                && visit(p, v, end + 1, vi + 1, memo)
                        }
                    } else {
                        vi < v.len() && p[pi] == v[vi] && visit(p, v, pi + 1, vi + 1, memo)
                    }
                }
                byte => vi < v.len() && byte == v[vi] && visit(p, v, pi + 1, vi + 1, memo),
            }
        };
        memo.insert((pi, vi), result);
        result
    }
    visit(
        pattern.as_bytes(),
        value.as_bytes(),
        0,
        0,
        &mut BTreeMap::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALIASES: &str = "alias pci:v00008086d0000157Bsv*sd*bc02sc*i* e1000e\nalias usb:v0BDAp8812d*dc*dsc*dp*ic*isc*if* rtl88xxau\nalias pci:v0000AB[0-9]0d* test_driver";
    const BUILTIN: &str =
        "kernel/drivers/net/ethernet/intel/e1000e.ko\nkernel/drivers/base/foo-bar.ko";
    const DEP: &str = "kernel/drivers/net/ethernet/intel/e1000e.ko: kernel/drivers/net/ethernet/libphy.ko\nkernel/drivers/net/ethernet/libphy.ko:\nkernel/drivers/base/foo-bar.ko:";
    const PROC: &str =
        "e1000e 245760 0 - Live 0xffffffffc0000000\nlibphy 16384 1 e1000e, Live 0xffffffffc0001000";

    #[test]
    fn parses_all_metadata_sources_and_normalizes_names() {
        let (index, issues) = ModuleIndex::from_metadata(ALIASES, BUILTIN, DEP, PROC);
        assert!(issues.is_empty(), "{issues:?}");
        assert!(index.is_builtin("foo-bar"));
        assert!(index.is_loaded("e1000e"));
        assert!(index.is_present("libphy"));
        assert_eq!(index.dependency_closure("e1000e"), vec!["libphy"]);
    }

    #[test]
    fn resolves_loaded_builtin_available_and_missing_states() {
        let (index, issues) = ModuleIndex::from_metadata(ALIASES, BUILTIN, DEP, PROC);
        assert!(issues.is_empty());
        let pci = index.resolve(
            "pci:v00008086d0000157Bsv00008086sd00000000bc02sc00i00",
            None,
        );
        assert_eq!(pci.len(), 1);
        assert_eq!(pci[0].name, "e1000e");
        assert_eq!(pci[0].state, ModuleState::Loaded);

        let usb = index.resolve("usb:v0BDAp8812d0000dc00dsc00dp00ic00isc00if00", None);
        assert_eq!(usb[0].state, ModuleState::Missing);

        let built = index.resolve("", Some("foo-bar"));
        assert_eq!(built[0].name, "foo_bar");
        assert_eq!(built[0].state, ModuleState::Builtin);
        assert_eq!(built[0].match_source, MatchSource::DriverLink);

        let unknown = index.resolve("", Some("out_of_tree_driver"));
        assert_eq!(unknown[0].state, ModuleState::Unknown);
    }

    #[test]
    fn reports_malformed_lines_without_panicking() {
        let (_, aliases) = ModuleIndex::parse_aliases("alias only-two\nnot-an-alias");
        let (_, deps) = ModuleIndex::parse_dependencies("broken-entry");
        let (_, loaded) = ModuleIndex::parse_loaded("short record");
        assert_eq!(aliases.len(), 2);
        assert_eq!(deps.len(), 1);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn rejects_malformed_proc_modules_records() {
        let (loaded, issues) = ModuleIndex::parse_loaded(
            "valid_module 4096 0 - Live 0x0000\\nnon_numeric nope 0 - Live 0x0\\nbad_state 4096 0 - Broken 0x0\\nbad_address 4096 0 - Live xyz",
        );
        assert_eq!(loaded, BTreeSet::from(["valid_module".to_owned()]));
        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn parses_compressed_module_paths_and_escaped_dependency_paths() {
        let (builtin, builtin_issues) = ModuleIndex::parse_builtin(
            "kernel/drivers/net/foo-bar.ko.xz\nkernel/drivers/net/baz.ko.zst\nkernel/drivers/net/qux.ko.gz",
        );
        assert!(builtin_issues.is_empty(), "{builtin_issues:?}");
        assert!(builtin.contains("foo_bar"));
        assert!(builtin.contains("baz"));
        assert!(builtin.contains("qux"));

        let (dependencies, issues) = ModuleIndex::parse_dependencies(
            "kernel/drivers/net/my\\x20driver.ko.xz: kernel/drivers/net/helper\\x20module.ko.zst",
        );
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(
            dependencies.get("my driver"),
            Some(&vec!["helper module".to_owned()])
        );
    }

    #[test]
    fn reports_invalid_dependency_paths_instead_of_dropping_them() {
        let (dependencies, issues) = ModuleIndex::parse_dependencies(
            "kernel/drivers/net/good.ko: kernel/drivers/net/valid.ko invalid.o",
        );
        assert!(dependencies.is_empty());
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("invalid dependency module path"));
    }

    #[test]
    fn matches_question_marks_and_character_classes() {
        assert!(glob_match("pci:v0000AB[0-9]0d*", "pci:v0000AB70d123"));
        assert!(glob_match("usb:v*ic?isc[0-3]if*", "usb:v123ic1isc2if00"));
        assert!(!glob_match("usb:v*ic?isc[0-3]if*", "usb:v123ic1isc9if00"));
        assert!(glob_match("pci:v0000AB[!0-6]0d*", "pci:v0000AB70d123"));
        assert!(glob_match("pci:v0000AB[^0-6]0d*", "pci:v0000AB90d123"));
        assert!(!glob_match("pci:v0000AB[!0-6]0d*", "pci:v0000AB30d123"));
        assert!(!glob_match("pci:v0000AB[9-2]0d*", "pci:v0000AB50d123"));
        assert!(glob_match("pci:v0000AB[0-6", "pci:v0000AB[0-6"));
    }
}
