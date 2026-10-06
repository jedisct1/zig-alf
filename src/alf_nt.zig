//! ALF-n-t: a block cipher on (8 * n + t) bits, with n in [2, 15] and t in [0, 7].
//! See Algorithm 1 of the ALF paper.
//!
//! The first n bytes of a block live in a 128-bit register.
//! The remaining t bits sit in the first byte of a second register.

const std = @import("std");
const aes = std.crypto.core.aes;
const tables = @import("tables.zig");

pub const Block = aes.Block;

/// Largest round count of any (n, t).
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

/// Byte shuffle with the PSHUFB convention: a negative control byte gives zero.
fn shuffle(x: Block, comptime ctrl: *const [16]i8) Block {
    // For `@shuffle`, a negative index picks from the second vector, which is all zeros here.
    const mask = comptime blk: {
        var m: [16]i32 = undefined;
        for (ctrl, &m) |c, *index| index.* = if (c < 0) -1 else c;
        break :blk m;
    };
    const src: @Vector(16, u8) = x.toBytes();
    const zero: @Vector(16, u8) = @splat(0);
    const out: [16]u8 = @shuffle(u8, src, zero, mask);
    return Block.fromBytes(&out);
}

/// Mix the parity of the first column of U into the t extra bits.
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

/// The n-byte register X and the t-bit register E.
pub const State = struct { x: Block, e: Block };

/// Run one encryption round per key.
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

/// Encrypt one block.
///
/// Both buffers need n bytes, plus one for the extra bits when t > 0.
/// The unused high bits of that last byte are ignored on input and zero on output.
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

/// Extra step needed once before the decryption rounds.
pub fn decryptAuxiliary(comptime n: u8, x: Block) Block {
    const enc_sigma_ctrl = &tables.enc_sigma[n - tables.n_min];
    const zero_bytes: [16]u8 = @splat(0);
    return shuffle(x, enc_sigma_ctrl).encryptLast(Block.fromBytes(&zero_bytes));
}

/// Run one decryption round per key, last key first.
/// `decryptAuxiliary` must have been applied to `state.x` before.
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

/// Final step that recovers the plaintext bytes after the decryption rounds.
pub fn decryptSrf(comptime n: u8, x: Block) Block {
    const dec_tau_ctrl = &tables.dec_tau[n - tables.n_min];
    const zero_bytes: [16]u8 = @splat(0);
    return shuffle(x, dec_tau_ctrl).decryptLast(Block.fromBytes(&zero_bytes));
}

/// Decrypt one block.
/// The keys must come from `prepareDecryption`.
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

/// Turn encryption round keys into decryption round keys.
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

test "ALF-11-5 reference vector from Appendix C" {
    const n: u8 = 11;
    const t: u8 = 5;
    const rounds = roundCount(n, t);
    try std.testing.expectEqual(@as(u8, 14), rounds);

    // Same round keys as the example program in the paper.
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
