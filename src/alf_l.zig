//! ALF on a vector of 16-bit symbols, each in [0, q_i) (Appendix F.4 of the ALF paper).
//!
//! As many leading symbols as possible are packed into one integer X, up to 144 bits.
//! If the whole vector fits, X is encrypted as a single integer.
//!
//! Otherwise this is ALF-L.
//! The remaining symbols form Y, and five layers alternate:
//! X is encrypted with a key that depends on Y, then Y is masked with a keystream that depends on X.

const std = @import("std");
const ktm = @import("ktm.zig");
const alf_int = @import("alf_int.zig");
const alf_16t = @import("alf_16t.zig");
const prng = @import("prng.zig");

pub const Block = ktm.Block;

pub const Error = error{
    EmptyInput,
    LengthMismatch,
    SymbolOutOfRange,
    TooLong,
};

/// Largest modulus of the packed part X.
pub const max_packed_modulus = alf_int.max_modulus;

/// Largest number of symbols in a vector.
pub const max_len = std.math.maxInt(u48);

/// The moduli of a vector.
/// A modulus of 0 stands for 2^16.
///
/// For more than one symbol, `same` and `distinct` give unrelated ciphertexts,
/// even if every entry of the `distinct` list is equal.
pub const Moduli = union(enum) {
    same: u16,
    distinct: []const u16,

    fn at(self: Moduli, i: usize) u32 {
        return prng.fullModulus(switch (self) {
            .same => |q| q,
            .distinct => |qs| qs[i],
        });
    }

    fn from(self: Moduli, start: usize) Moduli {
        return switch (self) {
            .same => self,
            .distinct => |qs| .{ .distinct = qs[start..] },
        };
    }
};

pub const Split = struct { lambda: usize, q_lambda: u160 };

/// How many leading symbols of an n-symbol vector are packed into X,
/// and the product of their moduli.
/// A `distinct` list must have at least n entries.
pub fn selectLambda(moduli: Moduli, n: usize) Split {
    if (moduli == .distinct) std.debug.assert(moduli.distinct.len >= n);
    var q: u160 = 1;
    var lambda: usize = 0;
    while (lambda < n) : (lambda += 1) {
        const next = std.math.mul(u160, q, moduli.at(lambda)) catch break;
        if (next > max_packed_modulus) break;
        q = next;
    }
    return .{ .lambda = lambda, .q_lambda = q };
}

fn packX(symbols: []const u16, moduli: Moduli) u160 {
    var x: u160 = 0;
    for (symbols, 0..) |p, i| x = x * moduli.at(i) + p;
    return x;
}

/// Divide x by d, for d up to 2^32, and return the remainder.
/// A plain 160-bit division is several times slower.
fn divRem(x: *u160, d: u64) u64 {
    var rem: u64 = 0;
    var quotient: u160 = 0;
    comptime var shift = 128;
    inline while (shift >= 0) : (shift -= 32) {
        const cur = (rem << 32) | @as(u32, @truncate(x.* >> shift));
        quotient |= @as(u160, cur / d) << shift;
        rem = cur % d;
    }
    x.* = quotient;
    return rem;
}

fn unpackX(x_in: u160, moduli: Moduli, out: []u16) void {
    var x = x_in;
    var end = out.len;
    while (end > 0) {
        // Handle the trailing symbols that fit in 32 bits together,
        // so that X is divided once per group and not once per symbol.
        var start = end;
        var group_modulus: u64 = 1;
        while (start > 0) : (start -= 1) {
            const next = group_modulus * moduli.at(start - 1);
            if (next > 1 << 32) break;
            group_modulus = next;
        }
        var group = divRem(&x, group_modulus);

        var i = end;
        while (i > start) {
            i -= 1;
            const q = moduli.at(i);
            out[i] = @intCast(group % q);
            group /= q;
        }
        end = start;
    }
}

fn domain(moduli: Moduli, n: usize) ktm.Domain {
    if (n == 1) return .{ .integer = moduli.at(0) };
    return switch (moduli) {
        .same => |q| .{ .same = .{ .n = @intCast(n), .q = q } },
        .distinct => |qs| .{ .distinct = qs },
    };
}

/// Round keys for encrypting X, bound to the current Y.
fn layerAKeys(tweaked: ktm.State, y: []const u16, d: u8) [alf_16t.rounds]Block {
    var s = ktm.smacR(tweaked, Block.fromBytes(&ktm.one_star));
    s = ktm.sCompress(s, y);
    var round_keys: [alf_16t.rounds]Block = undefined;
    ktm.deriveRoundKeys(16, alf_16t.rounds, s, d, &round_keys);
    return round_keys;
}

/// Keystream generator for masking Y, bound to the current X.
fn layerBPrng(tweaked: ktm.State, x: u160, d: u8) prng.ModPrng {
    var x_lo: [16]u8 = undefined;
    std.mem.writeInt(u128, &x_lo, @truncate(x), .little);
    const s = ktm.smacR(tweaked, Block.fromBytes(&x_lo));

    const x_hi: u32 = @intCast(x >> 128);
    var f: [3]ktm.State = undefined;
    for (&f, 1..) |*out, c| out.* = ktm.initFinal(s, (x_hi << 16) | (@as(u32, d) << 8) | @as(u32, @intCast(c)));

    // The paper leaves out the first block of the first two outputs.
    return .init(.{ f[0].a2, f[0].a3, f[1].a2, f[1].a3, f[2].a1, f[2].a2, f[2].a3 });
}

const Direction = enum { encrypt, decrypt };

fn applyCipher(comptime dir: Direction, cipher: *const alf_int.Cipher, x: u160) u160 {
    return (if (dir == .encrypt) cipher.encrypt(x) else cipher.decrypt(x)) catch unreachable;
}

fn applyKeystream(comptime dir: Direction, generator: *prng.ModPrng, y: []u16, moduli: Moduli) void {
    const block_len = prng.ModPrng.block_len;
    var shared: [block_len]u16 = undefined;
    if (moduli == .same) @memset(&shared, moduli.same);

    var i: usize = 0;
    while (i < y.len) : (i += block_len) {
        const count = @min(block_len, y.len - i);
        const qs = switch (moduli) {
            .same => shared[0..count],
            .distinct => |all| all[i..][0..count],
        };
        var samples: [block_len]u16 = undefined;
        generator.nextBlock(qs, samples[0..count]);
        for (y[i..][0..count], samples[0..count], qs) |*symbol, sample, q16| {
            const q = prng.fullModulus(q16);
            symbol.* = @intCast(switch (dir) {
                .encrypt => (@as(u32, symbol.*) + sample) % q,
                .decrypt => (@as(u32, symbol.*) + q - sample) % q,
            });
        }
    }
}

fn validate(moduli: Moduli, input: []const u16, out: []const u16) Error!void {
    if (input.len == 0) return error.EmptyInput;
    if (out.len != input.len) return error.LengthMismatch;
    if (input.len > max_len) return error.TooLong;
    if (moduli == .distinct and moduli.distinct.len != input.len) return error.LengthMismatch;
    for (input, 0..) |p, i| {
        if (p >= moduli.at(i)) return error.SymbolOutOfRange;
    }
}

fn crypt(
    comptime dir: Direction,
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    moduli: Moduli,
    input: []const u16,
    out: []u16,
) Error!void {
    try validate(moduli, input, out);

    const n = input.len;
    const split = selectLambda(moduli, n);
    const lambda = split.lambda;
    const q = split.q_lambda;
    const state = ktm.keyInit(key, app_id, domain(moduli, n));

    var x = packX(input[0..lambda], moduli);
    if (lambda < n) {
        const y = out[lambda..];
        if (y.ptr != input[lambda..].ptr) @memcpy(y, input[lambda..]);
        const y_moduli = moduli.from(lambda);
        const tweaked = ktm.tweakCompress(state, tweak);

        const layers: [5]u8 = switch (dir) {
            .encrypt => .{ 1, 2, 3, 4, 5 },
            .decrypt => .{ 5, 4, 3, 2, 1 },
        };
        for (layers) |d| {
            if (d % 2 == 1) {
                // X is full here, so its modulus is in the range ALF-16-t accepts.
                const cipher = alf_int.Cipher.fromAlf16tKeys(q, layerAKeys(tweaked, y, d)) catch unreachable;
                x = applyCipher(dir, &cipher, x);
            } else {
                var generator = layerBPrng(tweaked, x, d);
                applyKeystream(dir, &generator, y, y_moduli);
            }
        }
    } else if (q > 1) {
        const cipher = alf_int.Cipher.fromState(state, tweak, q) catch unreachable;
        x = applyCipher(dir, &cipher, x);
    }
    unpackX(x, moduli, out[0..lambda]);
}

/// Encrypt a vector of symbols into a vector with the same moduli.
///
/// `out` can be the same slice as `plaintext`.
/// Any other overlap is not allowed.
pub fn encrypt(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    moduli: Moduli,
    plaintext: []const u16,
    out: []u16,
) Error!void {
    return crypt(.encrypt, key, tweak, app_id, moduli, plaintext, out);
}

/// Inverse of `encrypt`.
pub fn decrypt(
    key: [16]u8,
    tweak: [16]u8,
    app_id: u64,
    moduli: Moduli,
    ciphertext: []const u16,
    out: []u16,
) Error!void {
    return crypt(.decrypt, key, tweak, app_id, moduli, ciphertext, out);
}

const test_key: [16]u8 = @splat(0xa5);
const test_tweak: [16]u8 = @splat(0x5a);

test "selectLambda fills X up to 2^144" {
    const expectEqual = std.testing.expectEqual;
    const full = max_packed_modulus;

    try expectEqual(Split{ .lambda = 9, .q_lambda = full }, selectLambda(.{ .same = 0 }, 256));
    try expectEqual(Split{ .lambda = 16, .q_lambda = 10_000_000_000_000_000 }, selectLambda(.{ .same = 10 }, 16));

    // Moduli of 1 take no room, so they still fit once X is full.
    const qs = [_]u16{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 1 };
    try expectEqual(Split{ .lambda = 11, .q_lambda = full }, selectLambda(.{ .distinct = &qs }, qs.len));
}

test "separate buffers, and same versus distinct moduli" {
    const ps: [40]u16 = @splat(5);
    const qs: [40]u16 = @splat(26);

    var separate: [ps.len]u16 = undefined;
    var in_place = ps;
    try encrypt(test_key, test_tweak, 0, .{ .same = 26 }, &ps, &separate);
    try encrypt(test_key, test_tweak, 0, .{ .same = 26 }, &in_place, &in_place);
    try std.testing.expectEqualSlices(u16, &separate, &in_place);

    var back: [ps.len]u16 = undefined;
    try decrypt(test_key, test_tweak, 0, .{ .same = 26 }, &separate, &back);
    try std.testing.expectEqualSlices(u16, &ps, &back);

    var distinct: [ps.len]u16 = undefined;
    try encrypt(test_key, test_tweak, 0, .{ .distinct = &qs }, &ps, &distinct);
    try std.testing.expect(!std.mem.eql(u16, &separate, &distinct));
}

test "invalid inputs are rejected" {
    const expectError = std.testing.expectError;
    var out: [3]u16 = undefined;
    try expectError(error.EmptyInput, encrypt(test_key, test_tweak, 0, .{ .same = 10 }, &.{}, out[0..0]));
    try expectError(error.LengthMismatch, encrypt(test_key, test_tweak, 0, .{ .same = 10 }, &.{ 1, 2 }, &out));
    try expectError(error.LengthMismatch, encrypt(test_key, test_tweak, 0, .{ .distinct = &.{ 10, 10 } }, &.{ 1, 2, 3 }, &out));
    try expectError(error.SymbolOutOfRange, encrypt(test_key, test_tweak, 0, .{ .same = 10 }, &.{ 1, 10, 3 }, &out));
    try expectError(error.SymbolOutOfRange, decrypt(test_key, test_tweak, 0, .{ .distinct = &.{ 10, 2, 10 } }, &.{ 1, 2, 3 }, &out));
}
