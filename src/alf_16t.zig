//! ALF-16-t: AES-NI-based length-preserving block cipher of width (128 + t)
//! bits, t ∈ [0, 16]. Format-preserving for any Q ∈ (2^127, 2^144].
//!
//! Twelve full AES rounds form the core. Each round mixes a 16-bit auxiliary
//! register E into the first two columns of the AES state via column parity,
//! mirroring the (α, β, ρ) trick of ALF-n-t but without per-n shuffles.

const std = @import("std");
const aes_core = std.crypto.core.aes;

pub const Block = aes_core.Block;

pub const rounds = 12;
pub const k_group = 2;

pub const Error = error{
    InvalidWidthBits,
    ModulusOutOfRange,
    ValueOutOfRange,
    BufferTooSmall,
};

pub fn validate(comptime t: u8) Error!void {
    if (t > 16) return error.InvalidWidthBits;
}

/// Byte count of an ALF-16-t value: 16 bytes for X plus the bytes needed by E.
pub fn byteLength(comptime t: u8) u8 {
    return 16 + (t + 7) / 8;
}

fn maskE(comptime t: u8) u16 {
    if (t == 0) return 0;
    if (t >= 16) return 0xffff;
    return (@as(u16, 1) << @intCast(t)) - 1;
}

fn highByteMask(comptime t: u8) u8 {
    if (t <= 8) return 0;
    if (t >= 16) return 0xff;
    return (@as(u8, 1) << @intCast(t - 8)) - 1;
}

fn loadInteger(comptime t: u8, bytes: []const u8) u160 {
    var v: u160 = std.mem.readInt(u128, bytes[0..16], .little);
    if (t > 0 and t <= 8) {
        const low_mask: u8 = if (t == 8) 0xff else (@as(u8, 1) << @intCast(t)) - 1;
        v |= @as(u160, bytes[16] & low_mask) << 128;
    } else if (t > 8) {
        v |= @as(u160, bytes[16]) << 128;
        v |= @as(u160, bytes[17] & highByteMask(t)) << 136;
    }
    return v;
}

fn storeInteger(comptime t: u8, v: u160, out: []u8) void {
    std.mem.writeInt(u128, out[0..16], @truncate(v), .little);
    if (t > 0 and t <= 8) {
        const low_mask: u8 = if (t == 8) 0xff else (@as(u8, 1) << @intCast(t)) - 1;
        out[16] = @as(u8, @truncate(v >> 128)) & low_mask;
    } else if (t > 8) {
        out[16] = @truncate(v >> 128);
        out[17] = @as(u8, @truncate(v >> 136)) & highByteMask(t);
    }
}

/// Build the 16-byte "E broadcast" block:
/// (E0, E0, E0, E0, E1, E1, E1, E1, 0, 0, 0, 0, 0, 0, 0, 0).
fn broadcastE(e: u16) Block {
    const e0: u8 = @truncate(e);
    const e1: u8 = @truncate(e >> 8);
    var bytes: [16]u8 = @splat(0);
    @memset(bytes[0..4], e0);
    @memset(bytes[4..8], e1);
    return Block.fromBytes(&bytes);
}

/// Column parity packed into a single u16: (p1 << 8) | p0.
fn columnParity(u: Block) u16 {
    const b = u.toBytes();
    const p0 = b[0] ^ b[1] ^ b[2] ^ b[3];
    const p1 = b[4] ^ b[5] ^ b[6] ^ b[7];
    return (@as(u16, p1) << 8) | p0;
}

/// Run two forward rounds of ALF-16-t given a 2-element slice of round keys.
fn forwardRounds(comptime t: u8, round_keys: []const Block, x: *Block, e: *u16) void {
    for (round_keys) |rk| {
        const u = x.encrypt(rk);
        x.* = u.xorBlocks(broadcastE(e.*));
        if (t != 0) e.* = (e.* ^ columnParity(u)) & maskE(t);
    }
}

/// Run two reverse rounds in reverse order with the *decryption* round keys
/// (i.e. MC'(RK[i])). The auxiliary `aesenclast` step must already have been
/// applied to `x`. After this, `x` is in the post-aesdeclast form ready for
/// either another two-round chunk or the final SRF.
fn reverseRounds(comptime t: u8, dec_round_keys: []const Block, x: *Block, e: *u16) void {
    const zero_bytes: [16]u8 = @splat(0);
    const zero = Block.fromBytes(&zero_bytes);
    var i = dec_round_keys.len;
    while (i > 0) {
        i -= 1;
        x.* = x.decrypt(zero);
        if (t != 0) e.* = (e.* ^ columnParity(x.*)) & maskE(t);
        x.* = x.xorBlocks(dec_round_keys[i]).xorBlocks(broadcastE(e.*));
    }
}

fn auxStep(x: Block) Block {
    const zero_bytes: [16]u8 = @splat(0);
    return x.encryptLast(Block.fromBytes(&zero_bytes));
}

fn srfStep(x: Block) Block {
    const zero_bytes: [16]u8 = @splat(0);
    return x.decryptLast(Block.fromBytes(&zero_bytes));
}

/// Transform encryption round keys into decryption round keys: RK'[i] = MC'(RK[i]).
pub fn prepareDecryption(enc_keys: *const [rounds]Block, dec_keys: *[rounds]Block) void {
    for (enc_keys, dec_keys) |rk, *out| out.* = rk.invMixColumns();
}

/// FPE encrypt: maps a plaintext in [0, Q) to a ciphertext in [0, Q).
/// `q` must lie in (2^127, 2^144]; the implied width is t = ⌈log2 q⌉ - 128.
pub fn encryptInt(
    comptime t: u8,
    q: u160,
    round_keys: *const [rounds]Block,
    plaintext: u160,
) Error!u160 {
    comptime try validate(t);
    if (q <= (@as(u160, 1) << 127) or q > (@as(u160, 1) << (128 + t))) return error.ModulusOutOfRange;
    if (plaintext >= q) return error.ValueOutOfRange;

    var x_bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, &x_bytes, @truncate(plaintext), .little);
    var x = Block.fromBytes(&x_bytes);
    var e: u16 = @intCast((plaintext >> 128) & maskE(t));

    var i: usize = 0;
    while (i < rounds / k_group) : (i += 1) {
        const rks = round_keys[k_group * i .. k_group * i + k_group];
        while (true) {
            forwardRounds(t, rks, &x, &e);
            const v: u160 = combineXE(t, x, e);
            if (v < q) break;
        }
    }
    return combineXE(t, x, e);
}

fn combineXE(comptime t: u8, x: Block, e: u16) u160 {
    const b = x.toBytes();
    var v: u160 = std.mem.readInt(u128, &b, .little);
    if (t != 0) v |= @as(u160, e & maskE(t)) << 128;
    return v;
}

/// FPE decrypt: inverse of `encryptInt`.
pub fn decryptInt(
    comptime t: u8,
    q: u160,
    dec_round_keys: *const [rounds]Block,
    ciphertext: u160,
) Error!u160 {
    comptime try validate(t);
    if (q <= (@as(u160, 1) << 127) or q > (@as(u160, 1) << (128 + t))) return error.ModulusOutOfRange;
    if (ciphertext >= q) return error.ValueOutOfRange;

    var x_bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, &x_bytes, @truncate(ciphertext), .little);
    var x = Block.fromBytes(&x_bytes);
    var e: u16 = @intCast((ciphertext >> 128) & maskE(t));

    x = auxStep(x);
    var i: usize = rounds / k_group;
    while (i > 0) {
        i -= 1;
        const rks = dec_round_keys[k_group * i .. k_group * i + k_group];
        while (true) {
            reverseRounds(t, rks, &x, &e);
            const after_srf = srfStep(x);
            const v: u160 = combineXE(t, after_srf, e);
            if (v < q) {
                // SRF cancels the next aux step on consecutive iterations, but
                // when the check passes we need to update x. If this is the
                // final group, leave x in SRF form; otherwise re-apply aux for
                // the next group. Equivalently, SRF ∘ aux = I so we can simply
                // not apply SRF and continue.
                if (i == 0) x = after_srf;
                break;
            }
            // If the value is out of range we re-run the same 2 reverse rounds
            // on the current `x`. Since we did *not* apply SRF to `x`, the
            // next reverseRounds call operates on the post-aesdec form, which
            // is what it expects.
        }
    }
    return combineXE(t, x, e);
}

pub fn encrypt(
    comptime t: u8,
    q: u160,
    round_keys: *const [rounds]Block,
    plaintext: []const u8,
    ciphertext: []u8,
) Error!void {
    const len = comptime byteLength(t);
    if (plaintext.len < len or ciphertext.len < len) return error.BufferTooSmall;
    const pt = loadInteger(t, plaintext);
    const ct = try encryptInt(t, q, round_keys, pt);
    storeInteger(t, ct, ciphertext);
}

pub fn decrypt(
    comptime t: u8,
    q: u160,
    dec_round_keys: *const [rounds]Block,
    ciphertext: []const u8,
    plaintext: []u8,
) Error!void {
    const len = comptime byteLength(t);
    if (ciphertext.len < len or plaintext.len < len) return error.BufferTooSmall;
    const ct = loadInteger(t, ciphertext);
    const pt = try decryptInt(t, q, dec_round_keys, ct);
    storeInteger(t, pt, plaintext);
}

test "ALF-16-0 length-preserving round-trip (128-bit cipher)" {
    var enc_rk: [rounds]Block = undefined;
    for (&enc_rk, 0..) |*rk, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*b, j| b.* = @intCast((i * 16 + j + 1) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [rounds]Block = undefined;
    prepareDecryption(&enc_rk, &dec_rk);

    var rng = std.Random.DefaultPrng.init(42);
    const rand = rng.random();
    for (0..16) |_| {
        const pt = rand.int(u128);
        const q: u160 = 1 << 128;
        const ct = try encryptInt(0, q, &enc_rk, pt);
        try std.testing.expect(ct < q);
        const back = try decryptInt(0, q, &dec_rk, ct);
        try std.testing.expectEqual(@as(u160, pt), back);
    }
}

test "ALF-16-t length-preserving for t > 0" {
    const t: u8 = 12;
    var enc_rk: [rounds]Block = undefined;
    for (&enc_rk, 0..) |*rk, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*b, j| b.* = @intCast((i * 7 + j * 3 + 11) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [rounds]Block = undefined;
    prepareDecryption(&enc_rk, &dec_rk);

    var rng = std.Random.DefaultPrng.init(7);
    const rand = rng.random();
    const q: u160 = 1 << (128 + t);
    for (0..16) |_| {
        var pt: u160 = rand.int(u128);
        pt |= @as(u160, rand.uintLessThan(u16, @intCast(@as(u32, 1) << t))) << 128;
        const ct = try encryptInt(t, q, &enc_rk, pt);
        try std.testing.expect(ct < q);
        const back = try decryptInt(t, q, &dec_rk, ct);
        try std.testing.expectEqual(pt, back);
    }
}

test "ALF-16-t byte API at t=16 (full 144 bits)" {
    const t: u8 = 16;
    var enc_rk: [rounds]Block = undefined;
    for (&enc_rk, 0..) |*rk, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*b, j| b.* = @intCast((i * 23 + j * 5 + 13) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [rounds]Block = undefined;
    prepareDecryption(&enc_rk, &dec_rk);

    const q: u160 = 1 << (128 + t);
    var pt_bytes: [18]u8 = .{ 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x7f, 0xc1 };
    var ct_bytes: [18]u8 = undefined;
    var back_bytes: [18]u8 = undefined;
    try encrypt(t, q, &enc_rk, &pt_bytes, &ct_bytes);
    try decrypt(t, q, &dec_rk, &ct_bytes, &back_bytes);
    try std.testing.expectEqualSlices(u8, &pt_bytes, &back_bytes);
}

test "ALF-16-t FPE: round-trip with non-power-of-two Q" {
    const t: u8 = 16;
    // 144 bits of width, Q slightly below 2^144.
    const q: u160 = (@as(u160, 1) << 143) + (@as(u160, 1) << 100);
    var enc_rk: [rounds]Block = undefined;
    for (&enc_rk, 0..) |*rk, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*b, j| b.* = @intCast((i * 19 + j * 5 + 31) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [rounds]Block = undefined;
    prepareDecryption(&enc_rk, &dec_rk);

    var rng = std.Random.DefaultPrng.init(99);
    const rand = rng.random();
    for (0..32) |_| {
        const r1: u128 = rand.int(u128);
        const r2: u16 = rand.int(u16);
        var pt: u160 = @as(u160, r1) | (@as(u160, r2) << 128);
        pt %= q;
        const ct = try encryptInt(t, q, &enc_rk, pt);
        try std.testing.expect(ct < q);
        const back = try decryptInt(t, q, &dec_rk, ct);
        try std.testing.expectEqual(pt, back);
    }
}
