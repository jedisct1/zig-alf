//! Cycle-sliding format-preserving encryption built on top of ALF-n-t.
//!
//! Algorithm 2 of the ALF paper. With k = 2, the cipher applies two rounds at a
//! time and checks after each group whether the intermediate value lies in the
//! valid set [0, Q). If not, the same two rounds are applied again until it
//! does. Cycle-sliding guarantees ≥ r rounds of the underlying block cipher and
//! is strictly more responsive than classic cycle-walking (k = r).
//!
//! Decryption mirrors encryption: for each group (in reverse), apply k inverse
//! rounds and repeat until the result lies in [0, Q). Chaining `alf.decrypt`
//! calls works because the SRF of one call cancels the auxiliary step of the
//! next on the meaningful n bytes.

const std = @import("std");
const alf = @import("alf_nt.zig");
const tables = @import("tables.zig");

/// Fixed group size for ALF cycle-sliding.
pub const k: u8 = 2;

pub const Error = alf.Error || error{
    ModulusTooSmall,
    ModulusOutOfRange,
    ValueOutOfRange,
    InvalidRoundCount,
};

const Block = alf.Block;

fn maskByte(comptime t: u8) u8 {
    return if (t == 0) 0 else (@as(u8, 1) << t) - 1;
}

fn loadInteger(comptime n: u8, comptime t: u8, bytes: []const u8) u128 {
    var v: u128 = 0;
    for (0..n) |i| v |= @as(u128, bytes[i]) << @intCast(8 * i);
    if (t != 0) {
        const tail = bytes[n] & maskByte(t);
        v |= @as(u128, tail) << @intCast(8 * n);
    }
    return v;
}

fn storeInteger(comptime n: u8, comptime t: u8, v: u128, out: []u8) void {
    for (0..n) |i| out[i] = @truncate(v >> @intCast(8 * i));
    if (t != 0) out[n] = @as(u8, @truncate(v >> @intCast(8 * n))) & maskByte(t);
}

/// Width in bits of the cipher (n, t).
pub fn width(comptime n: u8, comptime t: u8) u8 {
    return 8 * n + t;
}

/// Total byte footprint of a plaintext/ciphertext (the trailing byte is
/// counted once even when t < 8).
pub fn byteLength(comptime n: u8, comptime t: u8) u8 {
    return n + @intFromBool(t != 0);
}

/// Pick the (n, t) pair that fits the given modulus Q for ALF-n-t FPE.
/// Returns null when Q ≤ 2^15 (use ALF-1-t) or Q > 2^127 (use ALF-16-t).
pub fn selectShape(q: u128) ?struct { n: u8, t: u8 } {
    if (q <= (@as(u128, 1) << 15)) return null;
    if (q > (@as(u128, 1) << 127)) return null;
    const w: u8 = @intCast(128 - @clz(q - 1));
    const n: u8 = w / 8;
    const t: u8 = w % 8;
    return .{ .n = n, .t = t };
}

fn validateModulus(comptime n: u8, comptime t: u8, q: u128) Error!void {
    const w = comptime width(n, t);
    if (q <= (@as(u128, 1) << 15)) return error.ModulusTooSmall;
    if (w < 128 and q > (@as(u128, 1) << @intCast(w))) return error.ModulusOutOfRange;
}

/// FPE encrypt: maps a plaintext in [0, Q) to a ciphertext in [0, Q).
pub fn encryptInt(
    comptime n: u8,
    comptime t: u8,
    q: u128,
    round_keys: []const Block,
    plaintext: u128,
) Error!u128 {
    comptime try alf.validate(n, t);
    try validateModulus(n, t, q);
    if (plaintext >= q) return error.ValueOutOfRange;
    if (round_keys.len == 0 or round_keys.len % k != 0) return error.InvalidRoundCount;

    var bytes: [16]u8 = @splat(0);
    storeInteger(n, t, plaintext, &bytes);
    var e_bytes: [16]u8 = @splat(0);
    if (t != 0) {
        e_bytes[0] = bytes[n] & maskByte(t);
        bytes[n] = 0;
    }
    var state: alf.State = .{
        .x = Block.fromBytes(&bytes),
        .e = Block.fromBytes(&e_bytes),
    };

    const groups = round_keys.len / k;
    var g: usize = 0;
    while (g < groups) : (g += 1) {
        const rks = round_keys[g * k .. g * k + k];
        while (true) {
            state = alf.encryptRounds(n, t, rks, state);
            if (stateInteger(n, t, state) < q) break;
        }
    }
    return stateInteger(n, t, state);
}

fn stateInteger(comptime n: u8, comptime t: u8, state: alf.State) u128 {
    const x_bytes = state.x.toBytes();
    var v: u128 = 0;
    for (0..n) |i| v |= @as(u128, x_bytes[i]) << @intCast(8 * i);
    if (t != 0) {
        const e_byte = state.e.toBytes()[0] & maskByte(t);
        v |= @as(u128, e_byte) << @intCast(8 * n);
    }
    return v;
}

/// Byte-oriented wrapper around `encryptInt`.
pub fn encrypt(
    comptime n: u8,
    comptime t: u8,
    q: u128,
    round_keys: []const Block,
    plaintext: []const u8,
    ciphertext: []u8,
) Error!void {
    const len = byteLength(n, t);
    if (plaintext.len < len or ciphertext.len < len) return error.BufferTooSmall;
    const pt_int = loadInteger(n, t, plaintext);
    const ct_int = try encryptInt(n, t, q, round_keys, pt_int);
    storeInteger(n, t, ct_int, ciphertext);
}

/// FPE decrypt: inverse of `encryptInt`.
pub fn decryptInt(
    comptime n: u8,
    comptime t: u8,
    q: u128,
    dec_round_keys: []const Block,
    ciphertext: u128,
) Error!u128 {
    comptime try alf.validate(n, t);
    try validateModulus(n, t, q);
    if (ciphertext >= q) return error.ValueOutOfRange;
    if (dec_round_keys.len == 0 or dec_round_keys.len % k != 0) return error.InvalidRoundCount;

    const groups = dec_round_keys.len / k;
    const len = byteLength(n, t);
    var buf_a: [16]u8 = @splat(0);
    var buf_b: [16]u8 = @splat(0);
    storeInteger(n, t, ciphertext, &buf_a);

    var src = &buf_a;
    var dst = &buf_b;
    var g: usize = groups;
    while (g > 0) {
        g -= 1;
        const rks = dec_round_keys[g * k .. g * k + k];
        while (true) {
            try alf.decrypt(n, t, rks, src[0..len], dst[0..len]);
            std.mem.swap(*[16]u8, &src, &dst);
            if (loadInteger(n, t, src[0..len]) < q) break;
        }
    }
    return loadInteger(n, t, src[0..len]);
}

pub fn decrypt(
    comptime n: u8,
    comptime t: u8,
    q: u128,
    dec_round_keys: []const Block,
    ciphertext: []const u8,
    plaintext: []u8,
) Error!void {
    const len = byteLength(n, t);
    if (ciphertext.len < len or plaintext.len < len) return error.BufferTooSmall;
    const ct_int = loadInteger(n, t, ciphertext);
    const pt_int = try decryptInt(n, t, q, dec_round_keys, ct_int);
    storeInteger(n, t, pt_int, plaintext);
}

test "selectShape picks tightest (n, t)" {
    {
        const s = selectShape(10_000_000_000).?;
        try std.testing.expectEqual(@as(u8, 4), s.n);
        try std.testing.expectEqual(@as(u8, 2), s.t);
    }
    {
        const s = selectShape((@as(u128, 1) << 127)).?;
        try std.testing.expectEqual(@as(u8, 15), s.n);
        try std.testing.expectEqual(@as(u8, 7), s.t);
    }
    try std.testing.expectEqual(@as(?@TypeOf(selectShape(0).?), null), selectShape(1 << 15));
    try std.testing.expectEqual(@as(?@TypeOf(selectShape(0).?), null), selectShape((@as(u128, 1) << 127) + 1));
}

test "FPE round-trip with k=2 over a non-trivial modulus" {
    @setEvalBranchQuota(20_000);
    const n: u8 = 6;
    const t: u8 = 6; // width 54 bits.
    const q: u128 = 10_000_000_000_000_000; // 16 decimal digits, fits in 54 bits.
    const r = alf.roundCount(n, t);

    var enc_rk: [alf.max_rounds]Block = undefined;
    for (enc_rk[0..r], 0..) |*rk, idx| {
        var bytes: [16]u8 = @splat(0);
        for (0..n) |i| bytes[i] = @intCast((idx * 47 + i * 11 + 9) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [alf.max_rounds]Block = undefined;
    alf.prepareDecryption(n, enc_rk[0..r], dec_rk[0..r]);

    var rng = std.Random.DefaultPrng.init(0xDEAD_BEEF);
    const rand = rng.random();
    for (0..64) |_| {
        const pt = rand.uintLessThan(u128, q);
        const ct = try encryptInt(n, t, q, enc_rk[0..r], pt);
        try std.testing.expect(ct < q);
        const back = try decryptInt(n, t, q, dec_rk[0..r], ct);
        try std.testing.expectEqual(pt, back);
    }
}

test "FPE permutation property: distinct inputs map to distinct outputs" {
    const n: u8 = 3;
    const t: u8 = 0;
    const q: u128 = 50000; // small enough to enumerate
    const r = alf.roundCount(n, t);

    var enc_rk: [alf.max_rounds]Block = undefined;
    for (enc_rk[0..r], 0..) |*rk, idx| {
        var bytes: [16]u8 = @splat(0);
        for (0..n) |i| bytes[i] = @intCast((idx * 7 + i * 3 + 1) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [alf.max_rounds]Block = undefined;
    alf.prepareDecryption(n, enc_rk[0..r], dec_rk[0..r]);

    // Sample 200 plaintexts and verify ciphertexts are unique and bounded.
    var seen: std.AutoHashMapUnmanaged(u128, void) = .empty;
    defer seen.deinit(std.testing.allocator);
    var pt: u128 = 0;
    while (pt < 200) : (pt += 1) {
        const ct = try encryptInt(n, t, q, enc_rk[0..r], pt);
        try std.testing.expect(ct < q);
        try std.testing.expect(!seen.contains(ct));
        try seen.put(std.testing.allocator, ct, {});
        const back = try decryptInt(n, t, q, dec_rk[0..r], ct);
        try std.testing.expectEqual(pt, back);
    }
}
