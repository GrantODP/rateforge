use algos_common::token_bucket::TokenLimit;
use aya_ebpf::{
    bindings::sk_action,
    helpers::gen::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[map]
static TOKEN_BUCKET: RateBucket = RateBucket::with_max_entries(4, 0);

type RateBucket = HashMap<u64, TokenLimit>;

#[cgroup_skb]
pub fn cgroup_egress_tknb(ctx: SkBuffContext) -> i32 {
    info!(&ctx, "EGRESS");
    match try_token(ctx, &TOKEN_BUCKET, 1) {
        Ok(ret) => ret,
        Err(_) => sk_action::SK_PASS as i32,
    }
}
#[cgroup_skb]
pub fn cgroup_ingress_tknb(ctx: SkBuffContext) -> i32 {
    info!(&ctx, "INGRESS");
    match try_token(ctx, &TOKEN_BUCKET, 0) {
        Ok(ret) => ret,
        Err(_) => sk_action::SK_PASS as i32,
    }
}

fn try_token(ctx: SkBuffContext, bucket: &RateBucket, bucket_id: u64) -> Result<i32, ()> {
    unsafe {
        info!(
            &ctx,
            "--------------------------------------------------------------"
        );

        let cid = bpf_get_current_cgroup_id();
        let x = bpf_get_current_cgroup_id();
        info!(&ctx, "PID: {}", bpf_get_current_pid_tgid() >> 32);
        info!(&ctx, "CID: {}", bpf_get_current_cgroup_id());
        info!(&ctx, "CTX: {}", x);

        let state = bucket.get_ptr_mut(&bucket_id);
        if let Some(token) = state {
            let now = bpf_ktime_get_ns();
            let elapsed = now.saturating_sub((*token).last_tns());
            info!(&ctx, "Elapsed ns:{}", elapsed);

            info!(
                &ctx,
                "\nToken bucket : id:{} capacity:{}\nbucket:{}\nlast_tns:{}\nburst:{}",
                (*token).id(),
                (*token).capacity(),
                (*token).bucket(),
                (*token).last_tns(),
                (*token).burst()
            );

            if elapsed > (*token).burst() {
                let tokens_add = (*token).capacity() * elapsed / 1000000000;
                info!(&ctx, "Tokens add:{}", tokens_add);
                info!(&ctx, "Avaiable :{}", (*token).bucket());
                (*token).update_last_tns(now);
                (*token).refill(tokens_add);
            }

            let packet_len = ctx.len() as u64;

            info!(
                &ctx,
                " Packet len: {} vs Bucket {} vs Remaining {}",
                packet_len,
                (*token).capacity(),
                (*token).bucket()
            );

            if (*token).bucket() < packet_len {
                info!(&ctx, "DROP");
                return Ok(sk_action::SK_DROP as i32); // Drop packet
            }

            (*token).consume(packet_len);
        }
    }
    Ok(sk_action::SK_PASS as i32)
}
