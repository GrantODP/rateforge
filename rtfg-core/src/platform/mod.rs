use std::ffi::OsString;

use sysinfo::{RefreshKind, System};

use crate::control::Pid;

pub fn get_pids_by_name(name: &str) -> Option<Vec<Pid>> {
    let sys = System::new_with_specifics(RefreshKind::everything());
    let name = OsString::from(name);
    let procs = sys.processes_by_name(&name);
    let found_pids: Vec<Pid> = procs.map(|process| Pid(process.pid().into())).collect();

    if found_pids.is_empty() {
        None
    } else {
        Some(found_pids)
    }
}
