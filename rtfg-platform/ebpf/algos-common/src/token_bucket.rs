#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TokenLimit {
    /// Max capacity = Bytes per second
    pub token_capacity: u64,

    /// Current available bytes to process
    pub token_bucket: u64,

    /// Period to allow rate to exceed limit
    pub burst_period: u64,

    /// Timestamp in nanoseconds for last refill
    pub last_tns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenLimit {}

pub const EGRESS_BUCKET: &str = "MANAGED_BUCKETS";

pub const INGRESS_BUCKET: &str = "MANAGED_BUCKETS";

pub const EGRESS_BUCKET_ID: u32 = 0;

pub const INGRESS_BUCKET_ID: u32 = 1;

impl TokenLimit {
    pub fn new(token_capacity: u64, burst: u64) -> Self {
        Self {
            token_capacity,
            burst_period: burst,
            token_bucket: token_capacity,
            last_tns: 0,
        }
    }
    pub fn capacity(&self) -> u64 {
        self.token_capacity
    }
    pub fn burst(&self) -> u64 {
        self.burst_period
    }
    pub fn bucket(&self) -> u64 {
        self.token_bucket
    }
    pub fn last_tns(&self) -> u64 {
        self.last_tns
    }

    pub fn update_last_tns(&mut self, now: u64) {
        self.last_tns = now;
    }

    pub fn consume(&mut self, count: u64) {
        self.token_bucket = self.token_bucket.saturating_sub(count);
    }

    pub fn refill(&mut self, count: u64) {
        self.token_bucket =
            core::cmp::min(self.token_capacity, self.token_bucket.saturating_add(count));
    }
}
