//! ALF-L: length- and format-preserving encryption of a vector of 16-bit
//! plaintext symbols (p_0, ..., p_{N-1}) with per-position moduli (q_0, ...,
//! q_{N-1}). Appendix F.4 of the ALF paper.
//!
//! The first λ symbols are packed into a 128..144-bit integer X (with Q_λ ≤
//! 2^144 maximised); the remainder Y = (p_λ, ..., p_{N-1}) is encrypted by an
//! additive ModPRNG keystream. The 5-step A-B-A-B-A scheme cross-feeds the
//! two halves: each A step re-keys ALF-16-t from the current Y via the KTM,
//! and each B step re-seeds ModPRNG from the current X.

const std = @import("std");
const aes_core = std.crypto.core.aes;
const ktm = @import("ktm.zig");
const alf16t = @import("alf_16t.zig");
const prng = @import("prng.zig");

pub const Block = aes_core.Block;

pub const Error = alf16t.Error || error{
    EmptyInput,
    XPartOutOfRange,
    YModulusOutOfRange,
    InvalidLambda,
};

/// Split (q_0, ..., q_{N-1}) into the largest prefix λ whose product Q_λ is
/// at most 2^144, and return (λ, Q_λ).
pub fn selectLambda(qs: []const u16) struct { lambda: u32, q_lambda: u160 } {
    var q: u160 = 1;
    var lam: u32 = 0;
    for (qs) |qi| {
        const norm: u160 = if (qi == 0) (@as(u160, 1) << 16) else qi;
        const next: u160 = q * norm;
        if (next > (@as(u160, 1) << 144)) break;
        q = next;
        lam += 1;
    }
    return .{ .lambda = lam, .q_lambda = q };
}

/// Pack the first λ symbols into a mixed-radix integer.
pub fn packX(ps: []const u16, qs: []const u16, lambda: u32) u160 {
    std.debug.assert(ps.len >= lambda and qs.len >= lambda);
    if (lambda == 0) return 0;
    var x: u160 = ps[0];
    var i: u32 = 1;
    while (i < lambda) : (i += 1) {
        const norm: u160 = if (qs[i] == 0) (@as(u160, 1) << 16) else qs[i];
        x = x * norm + ps[i];
    }
    return x;
}

/// Inverse of `packX`: writes the first λ symbols of `out` from the packed X.
pub fn unpackX(x_in: u160, qs: []const u16, lambda: u32, out: []u16) void {
    std.debug.assert(out.len >= lambda and qs.len >= lambda);
    if (lambda == 0) return;
    var x = x_in;
    var i = lambda;
    while (i > 1) {
        i -= 1;
        const norm: u160 = if (qs[i] == 0) (@as(u160, 1) << 16) else qs[i];
        out[i] = @intCast(x % norm);
        x /= norm;
    }
    out[0] = @intCast(x);
}

/// Derive ALF-16-t round keys for layer A_j from the KTM state + current Y.
fn deriveAKeys(post_tweak: ktm.State, y: []const u16, d: u8, out: *[12]Block) void {
    const state = ktm.sCompress(post_tweak, y);
    var buf: [12 * 16]u8 = undefined;
    ktm.deriveBytes(state, d, &buf);
    for (out, 0..) |*rk, i| rk.* = Block.fromBytes(buf[i * 16 ..][0..16]);
}

/// Initialise ModPRNG state for layer B_j from the KTM state + current X.
fn deriveBState(post_tweak: ktm.State, x: u160, d: u8) prng.BinPrng {
    const x_lo: u128 = @truncate(x);
    var x_lo_bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, &x_lo_bytes, x_lo, .little);

    const state = ktm.smacR(post_tweak, Block.fromBytes(&x_lo_bytes));
    const x_hi: u16 = @intCast(x >> 128);

    var picked: [3 * 48]u8 = undefined;
    var c: u8 = 1;
    while (c <= 3) : (c += 1) {
        const param: u32 = (@as(u32, x_hi) << 16) | (@as(u32, d) << 8) | c;
        const s = ktm.initFinal(state, param);
        const off = (c - 1) * 48;
        @memcpy(picked[off..][0..16], &s.a1.toBytes());
        @memcpy(picked[off + 16 ..][0..16], &s.a2.toBytes());
        @memcpy(picked[off + 32 ..][0..16], &s.a3.toBytes());
    }
    var seeds: [7]Block = undefined;
    for (&seeds, 0..) |*b, i| b.* = Block.fromBytes(picked[i * 16 ..][0..16]);
    return prng.BinPrng.init(seeds);
}

fn encryptYInPlace(prng_state: *prng.BinPrng, y: []u16, qs: []const u16) void {
    std.debug.assert(y.len == qs.len);
    var pool: prng.Pool32 = .{};
    for (y, qs) |*yv, q| {
        const sample = prng.modSample16(prng_state, &pool, q);
        const sum: u32 = @as(u32, yv.*) + sample;
        const q_norm: u32 = if (q == 0) (1 << 16) else q;
        yv.* = @intCast(sum % q_norm);
    }
}

fn decryptYInPlace(prng_state: *prng.BinPrng, y: []u16, qs: []const u16) void {
    std.debug.assert(y.len == qs.len);
    var pool: prng.Pool32 = .{};
    for (y, qs) |*yv, q| {
        const sample = prng.modSample16(prng_state, &pool, q);
        const q_norm: u32 = if (q == 0) (1 << 16) else q;
        const diff: u32 = (@as(u32, yv.*) + q_norm - @as(u32, sample)) % q_norm;
        yv.* = @intCast(diff);
    }
}

/// Encrypt a single ALF-L plaintext vector. `qs` provides per-position moduli
/// (1..2^16; the value 0 is interpreted as 2^16 per Appendix F.4). `out` must
/// have the same length as `plaintext`.
pub fn encrypt(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    qs: []const u16,
    plaintext: []const u16,
    out: []u16,
) Error!void {
    if (plaintext.len == 0) return error.EmptyInput;
    if (plaintext.len != qs.len or out.len != qs.len) return error.YModulusOutOfRange;
    for (plaintext, qs) |p, q| {
        const q_norm: u32 = if (q == 0) (1 << 16) else q;
        if (@as(u32, p) >= q_norm) return error.XPartOutOfRange;
    }

    const sel = selectLambda(qs);
    const lambda = sel.lambda;
    const q_lambda = sel.q_lambda;
    if (lambda == 0) return error.InvalidLambda;

    // KTM: KeyInit absorbs (Q-1, N, AppID, key, q-vector) then tweak compress.
    const state = ktm.keyInit(key, app_id, @intCast(plaintext.len), @intCast(q_lambda - 1), qs);
    const post_tweak = ktm.tweakCompress(state, tweak);

    var x = packX(plaintext, qs, lambda);

    // Y mutates across the B layers; allocate working copy.
    var y_storage: [256]u16 = undefined;
    const y_len = plaintext.len - lambda;
    std.debug.assert(y_len <= y_storage.len);
    const y = y_storage[0..y_len];
    @memcpy(y, plaintext[lambda..]);
    const y_qs = qs[lambda..];

    if (q_lambda <= (@as(u160, 1) << 127)) return error.InvalidLambda;
    const t_used: u8 = @intCast(160 - @clz(q_lambda - 1) - 128);

    try runLayerA(post_tweak, t_used, q_lambda, &x, y, 1);
    try runLayerB(post_tweak, x, y, y_qs, 2);
    try runLayerA(post_tweak, t_used, q_lambda, &x, y, 3);
    try runLayerB(post_tweak, x, y, y_qs, 4);
    try runLayerA(post_tweak, t_used, q_lambda, &x, y, 5);

    unpackX(x, qs, lambda, out[0..lambda]);
    @memcpy(out[lambda..], y);
}

/// Decrypt a single ALF-L ciphertext vector. Reverses the A-B-A-B-A pipeline.
pub fn decrypt(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    qs: []const u16,
    ciphertext: []const u16,
    out: []u16,
) Error!void {
    if (ciphertext.len == 0) return error.EmptyInput;
    if (ciphertext.len != qs.len or out.len != qs.len) return error.YModulusOutOfRange;
    for (ciphertext, qs) |c, q| {
        const q_norm: u32 = if (q == 0) (1 << 16) else q;
        if (@as(u32, c) >= q_norm) return error.XPartOutOfRange;
    }

    const sel = selectLambda(qs);
    const lambda = sel.lambda;
    const q_lambda = sel.q_lambda;
    if (lambda == 0) return error.InvalidLambda;
    if (q_lambda <= (@as(u160, 1) << 127)) return error.InvalidLambda;

    const state = ktm.keyInit(key, app_id, @intCast(ciphertext.len), @intCast(q_lambda - 1), qs);
    const post_tweak = ktm.tweakCompress(state, tweak);

    var x = packX(ciphertext, qs, lambda);

    var y_storage: [256]u16 = undefined;
    const y_len = ciphertext.len - lambda;
    std.debug.assert(y_len <= y_storage.len);
    const y = y_storage[0..y_len];
    @memcpy(y, ciphertext[lambda..]);
    const y_qs = qs[lambda..];

    const t_used: u8 = @intCast(160 - @clz(q_lambda - 1) - 128);

    try runLayerAInverse(post_tweak, t_used, q_lambda, &x, y, 5);
    try runLayerBInverse(post_tweak, x, y, y_qs, 4);
    try runLayerAInverse(post_tweak, t_used, q_lambda, &x, y, 3);
    try runLayerBInverse(post_tweak, x, y, y_qs, 2);
    try runLayerAInverse(post_tweak, t_used, q_lambda, &x, y, 1);

    unpackX(x, qs, lambda, out[0..lambda]);
    @memcpy(out[lambda..], y);
}

inline fn runLayerA(
    post_tweak: ktm.State,
    t: u8,
    q_lambda: u160,
    x: *u160,
    y: []const u16,
    d: u8,
) !void {
    var rk: [alf16t.rounds]Block = undefined;
    deriveAKeys(post_tweak, y, d, &rk);
    x.* = switch (t) {
        inline 0...16 => |ti| try alf16t.encryptInt(ti, q_lambda, &rk, x.*),
        else => return error.InvalidLambda,
    };
}

inline fn runLayerAInverse(
    post_tweak: ktm.State,
    t: u8,
    q_lambda: u160,
    x: *u160,
    y: []const u16,
    d: u8,
) !void {
    var rk: [alf16t.rounds]Block = undefined;
    deriveAKeys(post_tweak, y, d, &rk);
    var dec_rk: [alf16t.rounds]Block = undefined;
    alf16t.prepareDecryption(&rk, &dec_rk);
    x.* = switch (t) {
        inline 0...16 => |ti| try alf16t.decryptInt(ti, q_lambda, &dec_rk, x.*),
        else => return error.InvalidLambda,
    };
}

inline fn runLayerB(
    post_tweak: ktm.State,
    x: u160,
    y: []u16,
    y_qs: []const u16,
    d: u8,
) !void {
    var prng_state = deriveBState(post_tweak, x, d);
    encryptYInPlace(&prng_state, y, y_qs);
}

inline fn runLayerBInverse(
    post_tweak: ktm.State,
    x: u160,
    y: []u16,
    y_qs: []const u16,
    d: u8,
) !void {
    var prng_state = deriveBState(post_tweak, x, d);
    decryptYInPlace(&prng_state, y, y_qs);
}

test "pack/unpack round-trip" {
    const qs = [_]u16{ 10, 100, 16, 65535, 23 };
    const ps = [_]u16{ 7, 42, 9, 1234, 17 };
    const packed_x = packX(&ps, &qs, qs.len);
    var out: [5]u16 = undefined;
    unpackX(packed_x, &qs, qs.len, &out);
    try std.testing.expectEqualSlices(u16, &ps, &out);
}

test "selectLambda stops at 2^144" {
    const qs = [_]u16{ 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535 };
    const sel = selectLambda(&qs);
    try std.testing.expect(sel.lambda <= 9);
    try std.testing.expect(sel.q_lambda <= (@as(u160, 1) << 144));
}

test "ALF-L round-trip with mixed moduli" {
    @setEvalBranchQuota(20_000);
    const qs = [_]u16{
        // First 9 push Q_lambda over 2^127 but under 2^144.
        60000, 60000, 60000, 60000, 60000, 60000, 60000, 60000, 60000,
        // Remaining live in the Y tail.
        1000,  256,   10000, 50000, 1234,
    };
    const ps = [_]u16{
        12345, 33333, 1,    59999, 55555, 11111, 42, 7777, 32768,
        500,   100,   9999, 12345, 999,
    };
    const key: [16]u8 = .{ 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
    const tweak: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    var ct: [ps.len]u16 = undefined;
    try encrypt(key, tweak, 0xdeadbeefcafef00d, &qs, &ps, &ct);
    for (ct, qs) |c, q| {
        const q_norm: u32 = if (q == 0) (1 << 16) else q;
        try std.testing.expect(@as(u32, c) < q_norm);
    }

    var back: [ps.len]u16 = undefined;
    try decrypt(key, tweak, 0xdeadbeefcafef00d, &qs, &ct, &back);
    try std.testing.expectEqualSlices(u16, &ps, &back);
}
