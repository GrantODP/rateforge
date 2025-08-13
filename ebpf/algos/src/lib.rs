pub mod ebpf;
pub mod errors;
pub mod factory;
pub mod pins;
pub mod tokenb;
mod util;
pub use errors::Error;

// use algos_common::token_bucket::TokenLimit;
// use aya::Ebpf;
// use ebpf::{AttachmentKind, CgroupName};
// use log::info;
// use tokenb::TokenBucketProgram;
// use tokio::signal;
//
// use crate::util::*;

// #[tokio::main]
// async fn main() -> Result<(), anyhow::Error> {
//     // Ok(())
//     env_logger::init();
//     let ebpf = get_ebpf().unwrap();
//     // let mut ebpf2 = get_ebpf().await.unwrap();
//     println!("Size of ebpf:{}", std::mem::size_of::<Ebpf>());
//     // let rate = TokenLimit::new(1000 * 1024, 10_000);
//
//     // let mut program = TokenBucketProgram::new(10, ebpf::AttachmentKind::Egress(rate));
//     let cgroup2 = CgroupName::try_from("vivaldi").unwrap();
//     let mut program2 = TokenBucketProgram::new(11.into(), cgroup2, ebpf);
//
//     // let cgroup = CgroupName::from("firefox");
//     let rate2 = TokenLimit::new(0, 2000 * 1024, 10_000);
//
//     program2.apply_rate(AttachmentKind::Ingress(rate2)).unwrap();
//     program2.apply_rate(AttachmentKind::Egress(rate2)).unwrap();
//
//     program2.load().unwrap();
//     info!("Waiting for Ctrl-C...");
//     signal::ctrl_c().await.unwrap();
//     info!("Exiting...");
//     Ok(())
// }
