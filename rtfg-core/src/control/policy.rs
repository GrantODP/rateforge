use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::util::generate_rid;

#[derive(Debug, Serialize, Deserialize, Default, Eq, PartialEq, Hash, Clone, Copy)]
pub struct RuleId(pub u64);

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = format!("{:?}", self);
        write!(f, "{}", val)
    }
}
impl From<u64> for RuleId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl From<&RuleId> for u64 {
    fn from(value: &RuleId) -> Self {
        value.0
    }
}
#[derive(Debug, Hash, PartialEq, Eq, Default)]
pub struct Policy {
    down: Option<Rate>,
    up: Option<Rate>,
    id: RuleId,
}

impl Policy {
    pub fn new(down: Option<Rate>, up: Option<Rate>) -> Self {
        let id = generate_rid(down.as_ref(), up.as_ref());
        Policy { id, down, up }
    }

    pub fn down(&self) -> Option<&Rate> {
        self.down.as_ref()
    }

    pub fn up(&self) -> Option<&Rate> {
        self.up.as_ref()
    }

    pub fn id(&self) -> &RuleId {
        &self.id
    }
}

#[derive(Default, Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct Rate(pub u64);

#[derive(Default)]
pub struct PolicyBuilder {
    pub down: u64,
    pub up: u64,
    pub rid: Option<RuleId>,
    pub name: Option<String>,
}

impl PolicyBuilder {
    pub fn new() -> PolicyBuilder {
        Self::default()
    }
    pub fn id(mut self, id: u64) -> PolicyBuilder {
        self.rid = Some(id.into());
        self
    }

    pub fn down(mut self, rate: u64) -> PolicyBuilder {
        self.down = rate;
        self
    }
    pub fn up(mut self, rate: u64) -> PolicyBuilder {
        self.up = rate;
        self
    }

    pub fn name(mut self, name: String) -> PolicyBuilder {
        self.name = Some(name);
        self
    }

    pub fn build(self) -> Policy {
        let down = (self.down != 0).then_some(Rate(self.down));
        let up = (self.down != 0).then_some(Rate(self.down));
        let id = self.rid.unwrap_or(generate_rid(down.as_ref(), up.as_ref()));
        let process_name = self.name.unwrap_or(format!("policy{}", id));
        Policy { down, up, id }
    }
}

impl Rate {
    pub fn kbits(&self) -> u64 {
        self.0 * 8
    }
    pub fn mbits(&self) -> u64 {
        self.0 / 8000
    }
    pub fn kbs(&self) -> u64 {
        self.0
    }
    pub fn mbs(&self) -> u64 {
        self.0 / 1000
    }
    pub fn bytes(&self) -> u64 {
        self.0 * 1024
    }
}

impl From<u64> for Rate {
    fn from(value: u64) -> Self {
        Rate(value)
    }
}

impl FromStr for Rate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u64>()
            .map(Rate)
            .map_err(|e| format!("Invalid rate: {}", e))
    }
}
