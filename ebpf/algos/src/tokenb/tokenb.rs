pub use algos_common::token_bucket::TokenLimit;
use aya::{maps::HashMap, programs::cgroup_skb::CgroupSkbAttachType, Ebpf};
use log::info;

pub use crate::{
    ebpf::{AttachmentKind, CgroupName, ProgramId},
    Error,
};
use crate::{
    ebpf::{MapKind, ProgramFlags, ProgramKind},
    pins::{PinError, PinLocation, PinnedObject, PinnedObjectBuilder},
    tokenb::errors::TokenBucketError,
    util::*,
};

const EGRESS_BASE_PNAME: &str = "tokenbegress";
const INGRESS_BASE_PNAME: &str = "tokenbingress";

#[derive(Debug)]
pub struct TokenBucketProgram {
    pub id: ProgramId,
    ebpf: Ebpf,
    flags: ProgramFlags,
    cgroup: CgroupName,
}

impl TokenBucketProgram {
    pub fn new(id: ProgramId, cgroup: CgroupName, ebpf: Ebpf) -> TokenBucketProgram {
        let s = Self {
            id,
            flags: ProgramFlags::BLOCKED,
            ebpf,
            cgroup,
        };
        s
    }

    pub fn pin(&mut self) -> Result<PinnedObject, Error> {
        if self.flags == ProgramFlags::BLOCKED {
            no_traffic_error()?
        }

        let mut pin_builer = PinnedObjectBuilder::new();

        if self.flags.contains(ProgramFlags::EGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupEgressTknb.into(), &mut self.ebpf)
                .map_err(|err| Error::EbpfProgram(err))?;

            let location = PinLocation::new(&format!("{}{}", EGRESS_BASE_PNAME, self.id));
            info!("Pinning at {:?}", location);
            skb.pin(&location).map_err(|err| PinError::from(err))?;

            info!("Pinned at {:?}", location);
            pin_builer =
                pin_builer.program(self.id.into(), ProgramKind::CgroupEgressTknb, location);
        }
        if self.flags.contains(ProgramFlags::INGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupEgressTknb.into(), &mut self.ebpf)
                .map_err(|err| Error::EbpfProgram(err))?;

            let location = PinLocation::new(&format!("{}{}", INGRESS_BASE_PNAME, self.id));

            info!("Pinning at {:?}", location);
            skb.pin(&location).map_err(|err| PinError::from(err))?;

            info!("Pinned at {:?}", location);
            pin_builer =
                pin_builer.program(self.id.into(), ProgramKind::CgroupIngressTknb, location);
        }

        // let map: HashMap<_, u64, TokenLimit> = MapKind::TokenBucket
        //     .get_mut(&mut self.ebpf)
        //     .map_err(|err| Error::General(err.to_string()))?;
        // let location = PinLocation::new(&format!("tokenbmap{}", self.id));
        // map.pin(&location).map_err(|err| PinError::from(err))?;
        // pin_builer = pin_builer.map(MapKind::TokenBucket, location);

        self.flags = self.flags.union(ProgramFlags::PINNED);
        Ok(pin_builer.build())
    }

    pub fn unpin(&mut self) -> Result<(), Error> {
        if !self.flags.contains(ProgramFlags::PINNED) {
            Err(PinError::NotPinned(
                "Cant unpin a program not pinned".into(),
            ))?
        }

        if self.flags.contains(ProgramFlags::EGRESS) {
            let location = PinLocation::new(format!("{}{}", EGRESS_BASE_PNAME, self.id));
            let skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Egress)?;
            skb.unpin()?;
        }

        if self.flags.contains(ProgramFlags::INGRESS) {
            let location = PinLocation::new(format!("{}{}", INGRESS_BASE_PNAME, self.id));
            let skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Ingress)?;
            skb.unpin()?;
        }

        // let map: HashMap<_, u64, TokenLimit> = MapKind::TokenBucket
        //     .get_mut(&mut self.ebpf)
        //     .map_err(|err| Error::General(err.to_string()))?;
        // let location = PinLocation::new(&format!("tokenbmap{}", self.id));
        // map.pin(&location).map_err(|err| PinError::from(err))?;

        Ok(())
    }

    fn submit_rate_to_map(
        &mut self,
        key: u64,
        rate: TokenLimit,
        map: MapKind,
    ) -> Result<(), Error> {
        let mut map: HashMap<_, u64, TokenLimit> = map
            .get_mut(&mut self.ebpf)
            .map_err(|err| Error::General(err.to_string()))?;
        map.insert(key, rate, 0)?;
        Ok(())
    }

    pub fn apply_rate(&mut self, token: AttachmentKind<TokenLimit>) -> Result<(), Error> {
        match token {
            AttachmentKind::Ingress(tk) => {
                self.flags = self.flags.union(ProgramFlags::INGRESS);
                self.submit_rate_to_map(0, tk, MapKind::TokenBucket)?;
            }
            AttachmentKind::Egress(tk) => {
                self.flags = self.flags.union(ProgramFlags::EGRESS);
                self.submit_rate_to_map(1, tk, MapKind::TokenBucket)?;
            }
        }
        info!("TB Program Flags: {:?}", self.flags);
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), Error> {
        info!("TB Program Flags BEFORE LOAD: {:?}", self.flags);
        self.unpin_load()
    }

    fn pin_load(&mut self) -> Result<(), Error> {
        //should never be the case if program is pinned
        if self.flags == ProgramFlags::BLOCKED {
            no_traffic_error()?
        }

        info!("PIN LOAD TB Program Flags BEFORE LOAD: {:?}", self.flags);
        if self.flags.contains(ProgramFlags::EGRESS) {
            let location = PinLocation::new(format!("{}{}", EGRESS_BASE_PNAME, self.id));
            let mut skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Egress)?;
            load_attach_egress(&location, &mut skb)?;
        }

        if self.flags.contains(ProgramFlags::INGRESS) {
            let location = PinLocation::new(format!("{}{}", INGRESS_BASE_PNAME, self.id));
            let mut skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Ingress)?;
            load_attach_ingress(&location, &mut skb)?;
        }

        Ok(())
    }

    pub fn unload(&mut self) -> Result<(), Error> {
        self.unpin_unload()
    }

    fn unpin_load(&mut self) -> Result<(), Error> {
        if self.flags == ProgramFlags::BLOCKED {
            no_traffic_error()?
        }

        if self.flags.contains(ProgramFlags::EGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupEgressTknb.into(), &mut self.ebpf)?;

            load_attach_egress(&self.cgroup, skb)?;
        }
        if self.flags.contains(ProgramFlags::INGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupIngressTknb.into(), &mut self.ebpf)?;

            load_attach_ingress(&self.cgroup, skb)?;
        }

        Ok(())
    }

    fn unpin_unload(&mut self) -> Result<(), Error> {
        if self.flags.contains(ProgramFlags::EGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupEgressTknb.into(), &mut self.ebpf)?;
            skb.unload()?;
        }
        if self.flags.contains(ProgramFlags::INGRESS) {
            let skb = get_ebpf_cgroup(ProgramKind::CgroupIngressTknb.into(), &mut self.ebpf)?;
            skb.unload()?;
        }

        info!("Program unloaded");
        Ok(())
    }

    // fn pin_unload(&mut self) -> Result<(), Error> {
    //     if self.flags.contains(ProgramFlags::EGRESS) {
    //         let location = PinLocation::new(format!("{}{}", EGRESS_BASE_PNAME, self.id));
    //         let mut skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Egress)?;
    //         skb.unload()?;
    //     }
    //
    //     if self.flags.contains(ProgramFlags::INGRESS) {
    //         let location = PinLocation::new(format!("{}{}", INGRESS_BASE_PNAME, self.id));
    //         let mut skb = get_pinned_ebpf_cgroup(&location, CgroupSkbAttachType::Ingress)?;
    //         skb.unload()?;
    //     }
    //     Ok(())
    // }
    //
    pub fn cgroup(&self) -> &CgroupName {
        &self.cgroup
    }

    pub fn cgroup_mut(&mut self) -> &mut CgroupName {
        &mut self.cgroup
    }
    pub fn close(&mut self) -> Result<(), Error> {
        self.unload()?;
        self.cgroup.delete()?;
        Ok(())
    }
}

fn no_traffic_error() -> Result<(), Error> {
    return Err(TokenBucketError::NoTrafficDirection(
        "Program doesnt know who to attach to. Consider adding a applying a rate".into(),
    ))?;
}
// impl TokenBucketProgram {
// fn try_from_pinned(
//     value: PinnedObject,
//     cgroup: CgroupName,
//     ebpf: Ebpf,
// ) -> Result<Self, PinError> {
//     let mut flags = ProgramFlags::PINNED;
//     let mut program_id: ProgramId = Default::default();
//
//     let iter = value.into_iter();
//     if iter.len() == 0 {
//         return Err(PinError::EmptyPinObject(Default::default()));
//     }
//
//     for pin_type in iter {
//         match pin_type {
//             PinType::Program(id, kind, _) => {
//                 program_id = id.clone();
//                 match kind {
//                     ProgramKind::CgroupIngressTknb => {
//                         flags = flags.union(ProgramFlags::INGRESS);
//                     }
//                     ProgramKind::CgroupEgressTknb => {
//                         flags = flags.union(ProgramFlags::EGRESS);
//                     }
//                     _ => {}
//                 }
//             }
//             //map is managed by self
//             _ => {}
//         }
//     }
//
//     Ok(TokenBucketProgram {
//         id: program_id,
//         cgroup,
//         ebpf,
//         flags,
//         Some()
//     })
// }
// }
