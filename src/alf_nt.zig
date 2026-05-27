//! ALF-n-t: AES-NI-based length-preserving binary block cipher of width
//! (8 * n + t) bits, where n ∈ [2, 15] and t ∈ [0, 7].
//!
//! The cipher follows Algorithm 1 of the ALF paper. The state is split into a
//! main 128-bit register that stores n meaningful bytes (rest zero) plus an
//! auxiliary register whose first byte carries the unaligned t bits.

const std = @import("std");
const aes = std.crypto.core.aes;
const tables = @import("tables.zig");

pub const Block = aes.Block;

/// Maximum number of rounds across all (n, t) variants (achieved by ALF-2-t, t > 0).
pub const max_rounds = 28;

pub const Error = error{
    InvalidWidthBytes,
    InvalidWidthBits,
    BufferTooSmall,
};

pub fn validate(comptime n: u8, comptime t: u8) Error!void {
    if (n < 2 or n > 15) return error.InvalidWidthBytes;
    if (t > 7) return error.InvalidWidthBits;
}

/// Round count for a given (n, t).
pub fn roundCount(n: u8, t: u8) u8 {
    std.debug.assert(n >= 2 and n <= 15 and t <= 7);
    return tables.rounds[n - tables.n_min][@intFromBool(t != 0)];
}

fn maskByte(comptime t: u8) u8 {
    return if (t == 0) 0 else (@as(u8, 1) << t) - 1;
}

fn maskBlock(comptime t: u8) Block {
    var bytes: [16]u8 = @splat(0);
    bytes[0] = maskByte(t);
    return Block.fromBytes(&bytes);
}

/// PSHUFB-style byte permutation: `out[i] = if (ctrl[i] < 0) 0 else x[ctrl[i] & 15]`.
fn shuffle(x: Block, ctrl: *const [16]i8) Block {
    const src = x.toBytes();
    var out: [16]u8 = undefined;
    for (ctrl, &out) |c, *o| {
        if (c < 0) {
            o.* = 0;
        } else {
            const idx: u4 = @truncate(@as(u8, @bitCast(c)));
            o.* = src[idx];
        }
    }
    return Block.fromBytes(&out);
}

/// Compute (E ⊕ B ⊕ parity_first_column(U)) AND M, masking to the t low bits.
fn updateE(e: Block, u_in: Block, b: Block, m: Block) Block {
    const lanes: @Vector(4, u32) = @bitCast(u_in.toBytes());
    const fold16 = lanes ^ (lanes >> @splat(16));
    const fold8 = fold16 ^ (fold16 >> @splat(8));
    const parity_bytes: [16]u8 = @bitCast(fold8);
    const parity = Block.fromBytes(&parity_bytes);
    return e.xorBlocks(b).xorBlocks(parity).andBlocks(m);
}

fn loadState(comptime n: u8, comptime t: u8, input: []const u8) State {
    var x_bytes: [16]u8 = @splat(0);
    @memcpy(x_bytes[0..n], input[0..n]);
    var e_bytes: [16]u8 = @splat(0);
    if (t != 0) e_bytes[0] = input[n] & maskByte(t);
    return .{ .x = Block.fromBytes(&x_bytes), .e = Block.fromBytes(&e_bytes) };
}

fn storeState(comptime n: u8, comptime t: u8, x: Block, e: Block, output: []u8) void {
    @memcpy(output[0..n], x.toBytes()[0..n]);
    if (t != 0) output[n] = e.toBytes()[0] & maskByte(t);
}

/// (X, E) state pair used between rounds.
pub const State = struct { x: Block, e: Block };

/// Apply the supplied encryption round keys in order to the (X, E) state.
pub fn encryptRounds(
    comptime n: u8,
    comptime t: u8,
    round_keys: []const Block,
    state: State,
) State {
    const enc_sigma_ctrl = &tables.enc_sigma[n - tables.n_min];
    const enc_beta_ctrl = &tables.enc_beta[n - tables.n_min];
    const rho_ctrl = &tables.rho[n - tables.n_min];
    const m = maskBlock(t);
    const zero_bytes: [16]u8 = @splat(0);
    const b = Block.fromBytes(&zero_bytes);

    var x = state.x;
    var e = state.e;
    for (round_keys) |rk| {
        const u = shuffle(x, enc_sigma_ctrl).encrypt(rk);
        const x_new = u.xorBlocks(shuffle(u, enc_beta_ctrl)).xorBlocks(shuffle(e, rho_ctrl));
        if (t != 0) e = updateE(e, u, b, m);
        x = x_new;
    }
    return .{ .x = x, .e = e };
}

/// Encrypt an (8*n + t)-bit plaintext with the supplied encryption round keys.
///
/// `input` and `output` must each hold at least `n + (t != 0)` bytes; the high
/// (8 - t) bits of the trailing byte are treated as zero on input and produced
/// as zero on output.
pub fn encrypt(
    comptime n: u8,
    comptime t: u8,
    round_keys: []const Block,
    input: []const u8,
    output: []u8,
) Error!void {
    comptime try validate(n, t);
    const trail: usize = comptime @intFromBool(t != 0);
    if (input.len < n + trail or output.len < n + trail) return error.BufferTooSmall;

    var state = loadState(n, t, input);
    state = encryptRounds(n, t, round_keys, state);
    storeState(n, t, state.x, state.e, output);
}

/// Auxiliary step applied once before the first decryption round group.
pub fn decryptAuxiliary(comptime n: u8, x: Block) Block {
    const enc_sigma_ctrl = &tables.enc_sigma[n - tables.n_min];
    const zero_bytes: [16]u8 = @splat(0);
    return shuffle(x, enc_sigma_ctrl).encryptLast(Block.fromBytes(&zero_bytes));
}

/// Apply the supplied decryption round keys in *reverse* order to the (X, E)
/// state. The auxiliary step must already have been applied to `state.x`.
pub fn decryptRounds(
    comptime n: u8,
    comptime t: u8,
    dec_round_keys: []const Block,
    state: State,
) State {
    const dec_sigma_ctrl = &tables.dec_sigma[n - tables.n_min];
    const dec_beta_ctrl = &tables.dec_beta[n - tables.n_min];
    const rho_ctrl = &tables.rho[n - tables.n_min];
    const m = maskBlock(t);
    var b_bytes: [16]u8 = @splat(0);
    b_bytes[0] = tables.parityCompensation(n);
    const b = Block.fromBytes(&b_bytes);

    var x = state.x;
    var e = state.e;
    var i = dec_round_keys.len;
    while (i > 0) {
        i -= 1;
        const rk = dec_round_keys[i];
        const w = shuffle(x, dec_sigma_ctrl).decrypt(rk);
        if (t != 0) e = updateE(e, w.xorBlocks(rk), b, m);
        x = w.xorBlocks(shuffle(w, dec_beta_ctrl)).xorBlocks(shuffle(e, rho_ctrl));
    }
    return .{ .x = x, .e = e };
}

/// State Retrieval Function applied once after the last decryption round group.
pub fn decryptSrf(comptime n: u8, x: Block) Block {
    const dec_tau_ctrl = &tables.dec_tau[n - tables.n_min];
    const zero_bytes: [16]u8 = @splat(0);
    return shuffle(x, dec_tau_ctrl).decryptLast(Block.fromBytes(&zero_bytes));
}

/// Decrypt an (8*n + t)-bit ciphertext with the supplied decryption round keys
/// (as produced by `prepareDecryption`).
pub fn decrypt(
    comptime n: u8,
    comptime t: u8,
    dec_round_keys: []const Block,
    input: []const u8,
    output: []u8,
) Error!void {
    comptime try validate(n, t);
    const trail: usize = comptime @intFromBool(t != 0);
    if (input.len < n + trail or output.len < n + trail) return error.BufferTooSmall;

    var state = loadState(n, t, input);
    state.x = decryptAuxiliary(n, state.x);
    state = decryptRounds(n, t, dec_round_keys, state);
    state.x = decryptSrf(n, state.x);
    storeState(n, t, state.x, state.e, output);
}

/// Transform encryption round keys into decryption round keys per Eq. (9), (10).
pub fn prepareDecryption(
    comptime n: u8,
    enc_keys: []const Block,
    dec_keys: []Block,
) void {
    std.debug.assert(enc_keys.len == dec_keys.len);
    const enc_beta_ctrl = &tables.enc_beta[n - tables.n_min];
    const dec_alpha_ctrl = &tables.dec_alpha[n - tables.n_min];
    const a = Block.fromBytes(&tables.const_a[n - tables.n_min]);

    for (enc_keys, dec_keys) |rk, *out| {
        const folded = rk.xorBlocks(shuffle(rk, enc_beta_ctrl));
        const mixed = a.xorBlocks(shuffle(folded, dec_alpha_ctrl));
        out.* = mixed.invMixColumns();
    }
}

test "shuffle handles negative indices" {
    var bytes: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const blk = Block.fromBytes(&bytes);
    const ctrl: [16]i8 = .{ 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1 };
    const out = shuffle(blk, &ctrl).toBytes();
    try std.testing.expectEqual(@as(u8, 1), out[0]);
    try std.testing.expectEqual(@as(u8, 0), out[1]);
    try std.testing.expectEqual(@as(u8, 3), out[2]);
    try std.testing.expectEqual(@as(u8, 0), out[3]);
}

test "ALF-11-5 reference vector from Appendix C" {
    const n: u8 = 11;
    const t: u8 = 5;
    const rounds = roundCount(n, t);
    try std.testing.expectEqual(@as(u8, 14), rounds);

    // RK[r][i] = 16*r + i + 1 for i in [0, n); rest zero. From paper's main().
    var enc_rk: [14]Block = undefined;
    for (&enc_rk, 0..) |*rk, r| {
        var bytes: [16]u8 = @splat(0);
        for (0..n) |i| bytes[i] = @intCast(16 * r + i + 1);
        rk.* = Block.fromBytes(&bytes);
    }

    const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x1a };
    const expected = [_]u8{ 0xc4, 0x12, 0x73, 0x4f, 0x64, 0x7a, 0x7d, 0xaa, 0x3f, 0x73, 0x60, 0x13 };

    var output: [12]u8 = undefined;
    try encrypt(n, t, &enc_rk, &input, &output);
    try std.testing.expectEqualSlices(u8, &expected, &output);

    var dec_rk: [14]Block = undefined;
    prepareDecryption(n, &enc_rk, &dec_rk);
    var roundtrip: [12]u8 = undefined;
    try decrypt(n, t, &dec_rk, &output, &roundtrip);
    try std.testing.expectEqualSlices(u8, &input, &roundtrip);
}

test "round-trip across selected (n, t)" {
    @setEvalBranchQuota(10_000);
    const cases = [_]struct { n: u8, t: u8 }{
        .{ .n = 2, .t = 0 },  .{ .n = 3, .t = 0 },  .{ .n = 4, .t = 0 },
        .{ .n = 5, .t = 0 },  .{ .n = 6, .t = 0 },  .{ .n = 7, .t = 0 },
        .{ .n = 8, .t = 0 },  .{ .n = 13, .t = 0 }, .{ .n = 15, .t = 0 },
        .{ .n = 2, .t = 7 },  .{ .n = 3, .t = 4 },  .{ .n = 11, .t = 5 },
        .{ .n = 15, .t = 7 },
    };
    inline for (cases) |c| {
        const r = roundCount(c.n, c.t);
        var enc_rk: [max_rounds]Block = undefined;
        for (enc_rk[0..r], 0..) |*rk, idx| {
            var bytes: [16]u8 = @splat(0);
            for (0..c.n) |i| bytes[i] = @intCast((idx * 31 + i * 7 + 3) & 0xff);
            rk.* = Block.fromBytes(&bytes);
        }
        var dec_rk: [max_rounds]Block = undefined;
        prepareDecryption(c.n, enc_rk[0..r], dec_rk[0..r]);

        var input: [16]u8 = undefined;
        for (&input, 0..) |*b, i| b.* = @intCast((i * 13 + 5) & 0xff);
        if (c.t != 0) input[c.n] &= maskByte(c.t);

        const trail: usize = @intFromBool(c.t != 0);
        var ct: [16]u8 = undefined;
        var pt: [16]u8 = undefined;
        try encrypt(c.n, c.t, enc_rk[0..r], &input, &ct);
        try decrypt(c.n, c.t, dec_rk[0..r], &ct, &pt);
        try std.testing.expectEqualSlices(u8, input[0 .. c.n + trail], pt[0 .. c.n + trail]);
    }
}
