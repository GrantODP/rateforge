use std::num::ParseIntError;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct Pid(pub usize);

impl From<Pid> for u64 {
    fn from(value: Pid) -> u64 {
        value.0 as u64
    }
}

impl From<u32> for Pid {
    fn from(value: u32) -> Pid {
        Pid(value as usize)
    }
}

impl TryFrom<String> for Pid {
    type Error = ParseIntError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Pid::try_from(value.as_str())
    }
}
impl TryFrom<&str> for Pid {
    type Error = ParseIntError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let val = value.trim().parse::<usize>()?;
        Ok(Pid(val))
    }
}

impl Default for Pid {
    fn default() -> Self {
        Pid(0)
    }
}
