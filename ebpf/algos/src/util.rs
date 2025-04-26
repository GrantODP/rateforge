use std::{fmt::Debug, path::Path};

use aya::{
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, ProgramError},
    Ebpf, EbpfError,
};
use log::{debug, info, warn};

use crate::ebpf::ProgramKind;

#[cfg(feature = "ebpf_logging_enabled")]
fn enable_ebpf_logging(ebpf: &mut Ebpf) {
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    info!("Ebpf logger enabled");
}

pub fn get_ebpf() -> Result<Ebpf, EbpfError> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/algos"
    )))?;

    #[cfg(feature = "ebpf_loggin_enabled")]
    enable_ebpf_logging(&mut ebpf);
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    info!("Ebpf logger enabled");
    Ok(ebpf)
}

pub fn get_ebpf_cgroup<'a>(
    name: &str,
    ebpf: &'a mut Ebpf,
) -> Result<&'a mut CgroupSkb, aya::programs::ProgramError> {
    let program: &mut CgroupSkb = ebpf
        .program_mut(name)
        .ok_or(ProgramError::InvalidName { name: name.into() })?
        .try_into()?;
    info!("got cgroup {}", name);
    Ok(program)
}
pub fn get_pinned_ebpf_cgroup<'a, P: AsRef<Path>>(
    path: P,
    attatch_type: CgroupSkbAttachType,
) -> Result<CgroupSkb, aya::programs::ProgramError> {
    let program: CgroupSkb = CgroupSkb::from_pin(path, attatch_type)?;

    info!("got pinned cgroup");
    Ok(program)
}
pub fn get_token_bucket_ingress<'a>(
    ebpf: &'a mut Ebpf,
) -> Result<&'a mut CgroupSkb, aya::programs::ProgramError> {
    Ok(get_ebpf_cgroup(
        ProgramKind::CgroupIngressTknb.into(),
        ebpf,
    )?)
}
pub async fn get_token_bucket_egress<'a>(
    ebpf: &'a mut Ebpf,
) -> Result<&'a mut CgroupSkb, aya::programs::ProgramError> {
    Ok(get_ebpf_cgroup(ProgramKind::CgroupEgressTknb.into(), ebpf)?)
}
pub fn load_attach_egress<'a, P: AsRef<Path> + Debug>(
    cgroup_path: P,
    program: &'a mut CgroupSkb,
) -> Result<(), aya::programs::ProgramError> {
    let cgroup = std::fs::File::open(&cgroup_path)?;
    program.load()?;
    program.attach(
        &cgroup,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::Single,
    )?;

    info!("Loaded Ingress Program  at {:?}", cgroup_path);
    Ok(())
}
pub fn load_attach_ingress<'a, P: AsRef<Path> + Debug>(
    cgroup_path: P,
    program: &'a mut CgroupSkb,
) -> Result<(), aya::programs::ProgramError> {
    let cgroup = std::fs::File::open(&cgroup_path)?;
    program.load()?;
    program.attach(
        &cgroup,
        CgroupSkbAttachType::Ingress,
        CgroupAttachMode::Single,
    )?;
    info!("Loaded Ingress Program at {:?}", cgroup_path);

    Ok(())
}
