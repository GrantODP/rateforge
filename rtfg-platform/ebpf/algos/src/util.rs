use std::path::PathBuf;

use anyhow::{Context, Ok};
use aya::{
    maps::HashMap,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use algos_common::token_bucket::{
    TokenLimit, EGRESS_BUCKET, EGRESS_BUCKET_ID, INGRESS_BUCKET, INGRESS_BUCKET_ID,
};
use log::{info, debug, warn};

#[cfg(feature= "ebpf_logging_enabled")]
fn enable_ebpf_logging(ebpf: &mut Ebpf) {
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    info!("Ebpf logger enabled")
}

pub async fn get_ebpf() -> anyhow::Result<Ebpf> {
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
    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/algos"
    )))?;

    #[cfg(feature = "ebpf_loggin_enabled")]
    enable_ebpf_logging(&mut ebpf);

    println!("init logger");
    Ok(ebpf)
}

// use std::path::PathBuf;
//
// use anyhow::{Context, Ok};
// use aya::{
//     maps::HashMap,
//     programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
//     Ebpf,
// };
// use ebpf_common::token_bucket::{
//     TokenLimit, EGRESS_BUCKET, EGRESS_BUCKET_ID, INGRESS_BUCKET, INGRESS_BUCKET_ID,
// };
// use log::{debug, info, warn};
//
// mod util;
// pub async fn get_efpb() -> anyhow::Result<Ebpf> {
//     // Bump the memlock rlimit. This is needed for older kernels that don't use the
//     // new memcg based accounting, see https://lwn.net/Articles/837122/
//     let rlim = libc::rlimit {
//         rlim_cur: libc::RLIM_INFINITY,
//         rlim_max: libc::RLIM_INFINITY,
//     };
//     let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
//     if ret != 0 {
//         debug!("remove limit on locked memory failed, ret is: {}", ret);
//     }
//     // This will include your eBPF object file as raw bytes at compile-time and load it at
//     // runtime. This approach is recommended for most real-world use cases. If you would
//     // like to specify the eBPF program at runtime rather than at compile-time, you can
//     // reach for `Bpf::load_file` instead.
//     let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
//         env!("OUT_DIR"),
//         "/egress"
//     )))?;
//
//     if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
//         // This can happen if you remove all log statements from your eBPF program.
//         warn!("failed to initialize eBPF logger: {}", e);
//     }
//
//     println!("init logger");
//     Ok(ebpf)
// }
//
pub async fn get_ebpf_cgroup<'a>(
    name: &str,
    ebpf: &'a mut Ebpf,
) -> anyhow::Result<&'a mut CgroupSkb> {
    let program: &mut CgroupSkb = ebpf.program_mut(name).unwrap().try_into()?;

    println!("got cgroup {}", name);
    Ok(program)
}
pub async fn load_attach_egress<'a>(
    cgroup_path: &PathBuf,
    program: &'a mut CgroupSkb,
) -> anyhow::Result<()> {
    let cgroup = std::fs::File::open(cgroup_path)?;
    program.load()?;
    program.attach(&cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)
        .context("failed to attach the Cgroup program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Loaded Ingress Program {:?} at: {:?}",program, cgroup_path);
    Ok(())
}
pub async fn load_attach_ingress<'a>(
    cgroup_path: &PathBuf,
    program: &'a mut CgroupSkb,
) -> anyhow::Result<()> {
    let cgroup = std::fs::File::open(cgroup_path)?;
    program.load()?;
    program.attach(&cgroup, CgroupSkbAttachType::Ingress, CgroupAttachMode::Single)
        .context("failed to attach the Cgroup program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    info!("Loaded Ingress Program {:?} at: {:?}",program, cgroup_path);

    Ok(())
}
pub async fn update_egress_rate(rate: TokenLimit, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut map: HashMap<_, u32, TokenLimit> =
        HashMap::try_from(ebpf.map_mut(EGRESS_BUCKET).unwrap())?;

    map.insert(EGRESS_BUCKET_ID, rate, 0)?;
    Ok(())
}
pub async fn update_ingress_rate(rate: TokenLimit, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut map: HashMap<_, u32, TokenLimit> =
        HashMap::try_from(ebpf.map_mut(INGRESS_BUCKET).unwrap())?;
    map.insert(INGRESS_BUCKET_ID, rate, 0)?;

    Ok(())
}

