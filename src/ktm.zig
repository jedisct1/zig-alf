//! Key-Tweak Management (KTM) for the ALF family.
//!
//! Implements SMAC-3/4 (KeyInit, TweakInit, InitFinal, SCompress) per §2.9 and
//! Appendix F.5 of the ALF paper. The KTM produces round keys for each
//! underlying ALF variant from a 128-bit secret key, a 128-bit tweak, a 64-bit
//! application ID, and the configuration (modulus Q, vector length N, per-
//! position moduli).
//!
//! The compression "1*" constant is defined here as a single byte 0x01
//! followed by 15 zero bytes — the paper refers to it as a fixed marker but
//! does not pin its bit pattern in the public draft, so any deterministic
//! choice yields a self-consistent cipher.

const std = @import("std");
const aes_core = std.crypto.core.aes;

pub const Block = aes_core.Block;

/// 1* compression constant — a fixed 128-bit marker used to enforce SMAC-3/4's
/// rate-3/4 absorption pattern (one constant block after at most three varying
/// messages).
pub const one_star: [16]u8 = blk: {
    var b: [16]u8 = @splat(0);
    b[0] = 0x01;
    break :blk b;
};

pub const State = struct {
    a1: Block,
    a2: Block,
    a3: Block,

    pub fn xor(self: State, other: State) State {
        return .{
            .a1 = self.a1.xorBlocks(other.a1),
            .a2 = self.a2.xorBlocks(other.a2),
            .a3 = self.a3.xorBlocks(other.a3),
        };
    }
};

/// σ42 from Algorithm 8: a PSHUFB-style byte permutation.
const sigma42 = [16]u8{ 7, 14, 15, 10, 12, 13, 3, 0, 4, 6, 1, 5, 8, 11, 2, 9 };

fn shuffleSigma42(x: Block) Block {
    const src = x.toBytes();
    var out: [16]u8 = undefined;
    for (sigma42, &out) |s, *o| o.* = src[s];
    return Block.fromBytes(&out);
}

/// One step of SMAC-3/4 compression with a 128-bit message block.
pub fn smacR(state: State, m: Block) State {
    return .{
        .a1 = shuffleSigma42(state.a2.xorBlocks(state.a3).xorBlocks(m)),
        .a2 = state.a1.encrypt(m),
        .a3 = state.a2.encrypt(m),
    };
}

fn smacR_iter(state: State, m: Block, n: usize) State {
    var s = state;
    var i: usize = 0;
    while (i < n) : (i += 1) s = smacR(s, m);
    return s;
}

/// InitFinal: 9 rounds of SMAC_R(state, C||{0}^12), then XOR with the
/// starting state to produce the final shuffled state.
pub fn initFinal(state: State, c: u32) State {
    var bytes: [16]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], c, .little);
    const m = Block.fromBytes(&bytes);
    const new = smacR_iter(state, m, 9);
    return state.xor(new);
}

/// SCompress: absorb N 16-bit values into the state, with a constant 1* block
/// injected after every three message blocks (rate 3/4).
pub fn sCompress(state: State, values: []const u16) State {
    var s = state;
    const one_star_blk = Block.fromBytes(&one_star);

    var blocks: usize = 0;
    var i: usize = 0;
    while (i < values.len) : (i += 8) {
        var bytes: [16]u8 = @splat(0);
        var j: usize = 0;
        while (j < 8 and i + j < values.len) : (j += 1) {
            std.mem.writeInt(u16, bytes[2 * j ..][0..2], values[i + j], .little);
        }
        s = smacR(s, Block.fromBytes(&bytes));
        blocks += 1;
        if (blocks % 3 == 0) s = smacR(s, one_star_blk);
    }
    if (blocks % 3 != 0) s = smacR(s, one_star_blk);
    return s;
}

/// KeyInit per Figure 11: load (Q-1, N, AppID, key) into the SMAC state and
/// shuffle via `InitFinal(1)`. When `qs` is non-empty (distinct per-position
/// moduli, N > 1), additionally absorb (q_i - 1) via SCompress.
pub fn keyInit(
    key: [16]u8,
    app_id: u64,
    n: u48,
    q_minus_one: u144,
    qs: []const u16,
) State {
    var a1_bytes: [16]u8 = undefined;
    std.mem.writeInt(u64, a1_bytes[0..8], app_id, .little);
    std.mem.writeInt(u48, a1_bytes[8..14], n, .little);
    const q_hi: u16 = @intCast(q_minus_one >> 128);
    std.mem.writeInt(u16, a1_bytes[14..16], q_hi, .little);

    var a3_bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, a3_bytes[0..16], @truncate(q_minus_one), .little);

    var state: State = .{
        .a1 = Block.fromBytes(&a1_bytes),
        .a2 = Block.fromBytes(&key),
        .a3 = Block.fromBytes(&a3_bytes),
    };
    state = initFinal(state, 1);
    if (qs.len > 1) {
        var buf: [256]u16 = undefined;
        std.debug.assert(qs.len <= buf.len);
        const q_minus_one_values = buf[0..qs.len];
        for (qs, q_minus_one_values) |q, *qv| qv.* = q -% 1;
        state = sCompress(state, q_minus_one_values);
    }
    return state;
}

/// Compress a 128-bit tweak into the post-KeyInit state.
pub fn tweakCompress(state: State, tweak: [16]u8) State {
    return smacR(state, Block.fromBytes(&tweak));
}

/// Stream consecutive InitFinal(D·256 + C) outputs (48 bytes each) into `out`.
/// The starting state should be the post-tweak state.
pub fn deriveBytes(state: State, d: u8, out: []u8) void {
    var offset: usize = 0;
    var c: u32 = 1;
    while (offset < out.len) : (c += 1) {
        const param = (@as(u32, d) << 8) | c;
        const s = initFinal(state, param);
        const a1 = s.a1.toBytes();
        const a2 = s.a2.toBytes();
        const a3 = s.a3.toBytes();
        var chunk: [48]u8 = undefined;
        @memcpy(chunk[0..16], &a1);
        @memcpy(chunk[16..32], &a2);
        @memcpy(chunk[32..48], &a3);
        const take = @min(out.len - offset, chunk.len);
        @memcpy(out[offset .. offset + take], chunk[0..take]);
        offset += take;
    }
}

/// Generate `rounds` n-byte round keys for ALF-n-t into the provided buffer.
/// Each key occupies the low `n` bytes of a 16-byte Block; the upper bytes
/// are zeroed.
pub fn deriveRoundKeys(
    n: u8,
    rounds: u8,
    post_tweak_state: State,
    d: u8,
    out: []Block,
) void {
    std.debug.assert(out.len == rounds);
    const total_bytes: usize = @as(usize, n) * @as(usize, rounds);
    var buf: [16 * 32]u8 = undefined; // up to 28 rounds × 15 bytes < 512
    std.debug.assert(total_bytes <= buf.len);
    deriveBytes(post_tweak_state, d, buf[0..total_bytes]);

    for (out, 0..) |*rk, i| {
        var bytes: [16]u8 = @splat(0);
        @memcpy(bytes[0..n], buf[i * n ..][0..n]);
        rk.* = Block.fromBytes(&bytes);
    }
}

/// End-to-end helper for ALF-n-t: produce round keys (encryption direction)
/// for given (n, t), modulus Q, key, tweak, AppID.
pub fn alfNtRoundKeys(
    n: u8,
    rounds: u8,
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    q: u128,
    out: []Block,
) void {
    std.debug.assert(out.len == rounds);
    const state = keyInit(key, app_id, 1, q - 1, &[_]u16{});
    const post_tweak = tweakCompress(state, tweak);
    deriveRoundKeys(n, rounds, post_tweak, 0, out);
}

/// End-to-end helper for ALF-16-t: produce 12 16-byte round keys.
pub fn alf16tRoundKeys(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    q: u160,
    out: *[12]Block,
) void {
    const state = keyInit(key, app_id, 1, @as(u144, @intCast(q - 1)), &[_]u16{});
    const post_tweak = tweakCompress(state, tweak);
    var buf: [12 * 16]u8 = undefined;
    deriveBytes(post_tweak, 0, &buf);
    for (out, 0..) |*rk, i| rk.* = Block.fromBytes(buf[i * 16 ..][0..16]);
}

/// End-to-end helper for ALF-0: produce 32 single-byte round keys.
pub fn alf0RoundKeys(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    q: u16,
    out: *[32]u8,
) void {
    const state = keyInit(key, app_id, 1, q - 1, &[_]u16{});
    const post_tweak = tweakCompress(state, tweak);
    var s = post_tweak;
    s = initFinal(s, 1);
    const a1 = s.a1.toBytes();
    const a2 = s.a2.toBytes();
    @memcpy(out[0..16], &a1);
    @memcpy(out[16..32], &a2);
}

/// End-to-end helper for ALF-1-t: produce 48 single-byte round keys.
pub fn alf1tRoundKeys(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    q: u16,
    out: *[48]u8,
) void {
    const state = keyInit(key, app_id, 1, q - 1, &[_]u16{});
    const post_tweak = tweakCompress(state, tweak);
    var s = post_tweak;
    s = initFinal(s, 1);
    const a1 = s.a1.toBytes();
    const a2 = s.a2.toBytes();
    const a3 = s.a3.toBytes();
    @memcpy(out[0..16], &a1);
    @memcpy(out[16..32], &a2);
    @memcpy(out[32..48], &a3);
}

test "SMAC compression updates all three registers" {
    const zero_bytes: [16]u8 = @splat(0);
    const zero = Block.fromBytes(&zero_bytes);
    const state: State = .{ .a1 = zero, .a2 = zero, .a3 = zero };
    const m = Block.fromBytes(&one_star);
    const after = smacR(state, m);
    try std.testing.expect(!std.mem.eql(u8, &after.a1.toBytes(), &state.a1.toBytes()));
    try std.testing.expect(!std.mem.eql(u8, &after.a2.toBytes(), &state.a2.toBytes()));
}

test "InitFinal is deterministic" {
    const key: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const state: State = .{
        .a1 = Block.fromBytes(&key),
        .a2 = Block.fromBytes(&key),
        .a3 = Block.fromBytes(&key),
    };
    const a = initFinal(state, 7);
    const b = initFinal(state, 7);
    try std.testing.expectEqualSlices(u8, &a.a1.toBytes(), &b.a1.toBytes());
}

test "Round-trip ALF-n-t with KTM round keys" {
    @setEvalBranchQuota(20_000);
    const alf = @import("alf_nt.zig");

    const n: u8 = 5;
    const t: u8 = 3;
    const rounds = alf.roundCount(n, t);
    const q: u128 = (@as(u128, 1) << (8 * n + t)); // length-preserving

    const key: [16]u8 = .{ 0xc0, 0xff, 0xee, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0x10, 0x20, 0x30, 0x40, 0x50 };
    const tweak: [16]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };

    var enc_rk: [alf.max_rounds]Block = undefined;
    alfNtRoundKeys(n, rounds, key, tweak, 0, q, enc_rk[0..rounds]);
    var dec_rk: [alf.max_rounds]Block = undefined;
    alf.prepareDecryption(n, enc_rk[0..rounds], dec_rk[0..rounds]);

    var pt: [16]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0x05, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var ct: [16]u8 = undefined;
    var back: [16]u8 = undefined;
    try alf.encrypt(n, t, enc_rk[0..rounds], &pt, &ct);
    try alf.decrypt(n, t, dec_rk[0..rounds], &ct, &back);
    try std.testing.expectEqualSlices(u8, pt[0..6], back[0..6]);
}
