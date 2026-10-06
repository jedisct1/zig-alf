//! Format-preserving encryption of an integer in [0, Q), built on ALF-n-t.
//! See Algorithm 2 of the ALF paper.
//!
//! Rounds are applied two at a time.
//! After each pair, if the value is not below Q, the same pair is applied again until it is.
//! The paper calls this cycle-sliding.
//!
//! Decryption undoes the pairs in reverse order, with the same retry rule.

const std = @import("std");
const alf = @import("alf_nt.zig");
const tables = @import("tables.zig");

/// Number of rounds between two range checks.
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

pub fn width(comptime n: u8, comptime t: u8) u8 {
    return 8 * n + t;
}

/// Number of bytes a value takes.
pub fn byteLength(comptime n: u8, comptime t: u8) u8 {
    return n + @intFromBool(t != 0);
}

/// Smallest (n, t) that fits the modulus.
/// Null when Q is too small (use ALF-1-t) or too large (use ALF-16-t).
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

/// Encrypt an integer in [0, Q) to another integer in [0, Q).
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

/// Same as `encryptInt`, on little-endian bytes.
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

/// Inverse of `encryptInt`.
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

test "FPE permutation property: distinct inputs map to distinct outputs" {
    const n: u8 = 3;
    const t: u8 = 0;
    const q: u128 = 50000;
    const r = alf.roundCount(n, t);

    var enc_rk: [alf.max_rounds]Block = undefined;
    for (enc_rk[0..r], 0..) |*rk, idx| {
        var bytes: [16]u8 = @splat(0);
        for (0..n) |i| bytes[i] = @intCast((idx * 7 + i * 3 + 1) & 0xff);
        rk.* = Block.fromBytes(&bytes);
    }
    var dec_rk: [alf.max_rounds]Block = undefined;
    alf.prepareDecryption(n, enc_rk[0..r], dec_rk[0..r]);

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
