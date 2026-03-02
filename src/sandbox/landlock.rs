use crate::config::Config;
use crate::output;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::{Path, PathBuf};

const ABI_VERSION: ABI = ABI::V3;

pub fn apply(config: &Config, project_dir: &Path, verbose: bool) {
    if !config.landlock_enabled() {
        if verbose {
            output::verbose("Landlock: disabled by config/flag");
        }
        return;
    }

    match do_apply(config, project_dir, verbose) {
        Ok(status) => match status {
            RulesetStatus::FullyEnforced => {
                output::info("Landlock: fully enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                output::info(
                    "Landlock: partially enforced \
                     (kernel lacks some features)",
                );
            }
            RulesetStatus::NotEnforced => {
                output::warn(
                    "Landlock: not enforced \
                     (kernel too old, bwrap-only)",
                );
            }
        },
        Err(e) => {
            output::warn(&format!(
                "Landlock: failed to apply ({e}), \
                 falling back to bwrap-only"
            ));
        }
    }
}

/// Collect paths that need read-only access and paths that
/// need read-write access, then build and apply the ruleset.
fn do_apply(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<RulesetStatus, landlock::RulesetError> {
    let access_all = AccessFs::from_all(ABI_VERSION);
    let access_read = AccessFs::from_read(ABI_VERSION);

    let (ro_paths, rw_paths) = if config.lockdown_enabled() {
        collect_lockdown_paths(project_dir, verbose)
    } else {
        collect_normal_paths(config, project_dir, verbose)
    };

    let status = Ruleset::default()
        .handle_access(access_all)?
        .create()?
        .add_rules(path_beneath_rules(ro_paths, access_read))?
        .add_rules(path_beneath_rules(rw_paths, access_all))?
        .restrict_self()?;

    Ok(status.ruleset)
}

fn collect_lockdown_paths(
    project_dir: &Path,
    verbose: bool,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    // Root filesystem: read-only (bwrap needs "/" to set up mount
    // namespaces via `mount --make-rslave /`).  This covers all
    // subdirectories, so individual system paths below are technically
    // redundant but kept for documentation.
    ro.push(PathBuf::from("/"));

    // System paths: read-only
    for p in &[
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/sys",
        "/run", "/dev",
    ] {
        ro.push(PathBuf::from(p));
    }
    if verbose {
        output::verbose("Landlock lockdown: system ro");
    }

    // /proc: read-write (bwrap writes /proc/self/uid_map)
    rw.push(PathBuf::from("/proc"));

    // /tmp: read-write (only writable user location)
    rw.push(PathBuf::from("/tmp"));
    if verbose {
        output::verbose("Landlock lockdown: /tmp rw");
    }

    // Project: read-only
    ro.push(project_dir.to_path_buf());
    if verbose {
        output::verbose(&format!(
            "Landlock lockdown: {} ro",
            project_dir.display()
        ));
    }

    (ro, rw)
}

fn collect_normal_paths(
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let home = super::home_dir();
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    // Root filesystem: read-only (bwrap needs "/" to set up mount
    // namespaces via `mount --make-rslave /`).  This covers all
    // subdirectories, so individual system paths below are technically
    // redundant but kept for documentation.
    ro.push(PathBuf::from("/"));

    // System paths: read-only
    for p in &[
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/sys",
        "/run",
    ] {
        ro.push(PathBuf::from(p));
    }
    if verbose {
        output::verbose("Landlock: system paths ro");
    }

    // Writable system paths
    // /proc must be rw: bwrap writes /proc/self/uid_map for namespace setup
    rw.push(PathBuf::from("/proc"));
    rw.push(PathBuf::from("/tmp"));
    rw.push(PathBuf::from("/dev"));
    if verbose {
        output::verbose("Landlock: /proc, /tmp, /dev rw");
    }

    // /dev/shm
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        rw.push(shm);
    }

    // Project directory: read-write
    rw.push(project_dir.to_path_buf());
    if verbose {
        output::verbose(&format!("Landlock: {} rw", project_dir.display()));
    }

    // $HOME: read-write.  Inside the sandbox $HOME is a tmpfs,
    // so this allows tools (mise, gem, etc.) to create dirs.
    // bwrap ro-bind mounts for individual dotdirs still prevent
    // writes to those — filesystem permissions override Landlock.
    rw.push(home.clone());
    if verbose {
        output::verbose("Landlock: $HOME rw");
    }

    // Home dotdirs
    collect_home_paths(&home, &mut ro, &mut rw, verbose);

    // $HOME/.local: read-write
    let dot_local = home.join(".local");
    if dot_local.is_dir() {
        if verbose {
            output::verbose("Landlock: ~/.local rw");
        }
        rw.push(dot_local);
    }

    // $HOME/.claude.json: read-write
    let claude_json = home.join(".claude.json");
    if claude_json.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.claude.json rw");
        }
        rw.push(claude_json);
    }

    // $HOME/.gitconfig: read-only
    let gitconfig = home.join(".gitconfig");
    if gitconfig.is_file() {
        if verbose {
            output::verbose("Landlock: ~/.gitconfig ro");
        }
        ro.push(gitconfig);
    }

    // Extra user mounts
    for p in &config.rw_maps {
        rw.push(p.clone());
    }
    for p in &config.ro_maps {
        ro.push(p.clone());
    }
    if verbose && (!config.rw_maps.is_empty() || !config.ro_maps.is_empty()) {
        output::verbose("Landlock: extra maps");
    }

    // Docker socket
    if config.docker_enabled() {
        let sock = PathBuf::from("/var/run/docker.sock");
        if super::path_exists(&sock) {
            if verbose {
                output::verbose("Landlock: docker socket rw");
            }
            rw.push(sock);
        }
    }

    // GPU devices
    if config.gpu_enabled() {
        collect_gpu_paths(&mut rw, verbose);
    }

    // bwrap binary: read+execute (covered by from_read)
    if let Ok(bwrap) = super::bwrap::bwrap_binary_path() {
        if verbose {
            output::verbose(&format!("Landlock: bwrap {} ro", bwrap.display()));
        }
        ro.push(bwrap);
    }

    (ro, rw)
}

fn collect_home_paths(
    home: &Path,
    ro: &mut Vec<PathBuf>,
    rw: &mut Vec<PathBuf>,
    verbose: bool,
) {
    let entries = match std::fs::read_dir(home) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with('.') || name_str == "." || name_str == ".." {
            continue;
        }

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        if super::DOTDIR_DENY.contains(&name_str.as_ref()) {
            continue;
        }

        if super::DOTDIR_RW.contains(&name_str.as_ref()) {
            if verbose {
                output::verbose(&format!("Landlock: ~/{name_str} rw"));
            }
            rw.push(path);
        } else {
            if verbose {
                output::verbose(&format!("Landlock: ~/{name_str} ro"));
            }
            ro.push(path);
        }
    }
}

fn collect_gpu_paths(rw: &mut Vec<PathBuf>, verbose: bool) {
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("nvidia") {
                let p = entry.path();
                if verbose {
                    output::verbose(&format!(
                        "Landlock: gpu {} rw",
                        p.display()
                    ));
                }
                rw.push(p);
            }
        }
    }

    let dri = PathBuf::from("/dev/dri");
    if super::path_exists(&dri) {
        if verbose {
            output::verbose("Landlock: gpu /dev/dri rw");
        }
        rw.push(dri);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_disabled_is_noop() {
        let config = Config {
            no_landlock: Some(true),
            ..Config::default()
        };
        // Should return without error or panic
        apply(&config, Path::new("/tmp"), false);
    }

    #[test]
    fn apply_enabled_does_not_panic() {
        let config = Config::default();
        assert!(config.landlock_enabled());
        // On kernels without landlock this prints a warning;
        // on kernels with landlock it enforces rules.
        // Either way it must not panic.
        apply(&config, Path::new("/tmp"), false);
    }

    #[test]
    fn apply_lockdown_does_not_panic() {
        let config = Config {
            lockdown: Some(true),
            ..Config::default()
        };
        apply(&config, Path::new("/tmp"), false);
    }

    #[test]
    fn lockdown_paths_project_is_readonly() {
        let project = PathBuf::from("/home/user/project");
        let (ro, rw) = collect_lockdown_paths(&project, false);
        assert!(ro.contains(&project), "project must be in ro list");
        assert!(!rw.contains(&project), "project must not be in rw list");
    }

    #[test]
    fn lockdown_paths_tmp_is_writable() {
        let (_, rw) = collect_lockdown_paths(Path::new("/tmp/proj"), false);
        assert!(rw.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn normal_paths_project_is_writable() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            ..Config::default()
        };
        let project = PathBuf::from("/tmp/test-proj");
        let (_, rw) = collect_normal_paths(&config, &project, false);
        assert!(rw.contains(&project), "project must be in rw list");
    }

    #[test]
    fn normal_paths_root_is_readable() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            ..Config::default()
        };
        let (ro, _) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(
            ro.contains(&PathBuf::from("/")),
            "/ must be in ro list so bwrap can set up mount namespaces"
        );
    }

    #[test]
    fn lockdown_paths_root_is_readable() {
        let (ro, _) = collect_lockdown_paths(Path::new("/tmp/proj"), false);
        assert!(
            ro.contains(&PathBuf::from("/")),
            "/ must be in ro list so bwrap can set up mount namespaces"
        );
    }

    #[test]
    fn normal_paths_extra_maps_included() {
        let config = Config {
            no_gpu: Some(true),
            no_docker: Some(true),
            rw_maps: vec![PathBuf::from("/extra/rw")],
            ro_maps: vec![PathBuf::from("/extra/ro")],
            ..Config::default()
        };
        let (ro, rw) = collect_normal_paths(&config, Path::new("/tmp"), false);
        assert!(rw.contains(&PathBuf::from("/extra/rw")));
        assert!(ro.contains(&PathBuf::from("/extra/ro")));
    }
}
