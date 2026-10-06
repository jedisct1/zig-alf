//! ALF on a vector of 16-bit symbols, each in [0, q_i) (Appendix F.4 of the ALF paper).
//!
//! As many leading symbols as possible are packed into one integer X, up to 144 bits.
//! If the whole vector fits, X is encrypted as a single integer.
//!
//! Otherwise this is ALF-L.
//! The remaining symbols form Y, and five layers alternate:
//! X is encrypted with a key that depends on Y, then Y is masked with a keystream that depends on X.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;

const alf_16t = @import("alf_16t.zig");
const errors = @import("errors.zig");
const ktm = @import("ktm.zig");
const prng = @import("prng.zig");
const Alf = @import("alf_int.zig").Alf;
const ModPrng = prng.ModPrng;
const EmptyInputError = errors.EmptyInputError;
const SymbolOutOfRangeError = errors.SymbolOutOfRangeError;

const Direction = enum { encrypt, decrypt };

/// A cipher on vectors of symbols, that keeps every symbol below its modulus.
pub const AlfL = struct {
    pub const key_length = ktm.key_length;
    pub const tweak_length = ktm.tweak_length;
    /// The largest number of symbols in a vector.
    pub const max_length = math.maxInt(u48);
    /// The largest modulus of the packed part X.
    pub const max_packed_modulus = Alf.max_modulus;

    /// The moduli of a vector.
    /// A modulus of 0 stands for 2^16.
    ///
    /// For more than one symbol, `same` and `distinct` use unrelated keys,
    /// even if every entry of the `distinct` list is equal.
    pub const Moduli = union(enum) {
        same: u16,
        distinct: []const u16,

        fn at(moduli: Moduli, i: usize) u32 {
            return prng.fullModulus(switch (moduli) {
                .same => |q| q,
                .distinct => |qs| qs[i],
            });
        }

        fn from(moduli: Moduli, start: usize) Moduli {
            return switch (moduli) {
                .same => moduli,
                .distinct => |qs| .{ .distinct = qs[start..] },
            };
        }
    };

    /// Where a vector is cut between the packed part X and the rest.
    pub const Split = struct { lambda: usize, q_lambda: u160 };

    /// Returns how many leading symbols of an n-symbol vector are packed into X,
    /// and the product of their moduli.
    /// Asserts that a `distinct` list has at least `n` entries.
    pub fn selectLambda(moduli: Moduli, n: usize) Split {
        if (moduli == .distinct) assert(moduli.distinct.len >= n);
        var q: u160 = 1;
        var lambda: usize = 0;
        while (lambda < n) : (lambda += 1) {
            const next = math.mul(u160, q, moduli.at(lambda)) catch break;
            if (next > max_packed_modulus) break;
            q = next;
        }
        return .{ .lambda = lambda, .q_lambda = q };
    }

    /// Encrypts a vector of symbols into a vector with the same moduli.
    ///
    /// `c` can be the same slice as `m`.
    /// Any other overlap is not allowed.
    ///
    /// Asserts `c.len == m.len` and `m.len <= max_length`.
    /// Asserts that a `distinct` list has one modulus per symbol.
    pub fn encrypt(
        c: []u16,
        m: []const u16,
        moduli: Moduli,
        app_id: u64,
        tweak: [tweak_length]u8,
        key: [key_length]u8,
    ) (EmptyInputError || SymbolOutOfRangeError)!void {
        return crypt(.encrypt, c, m, moduli, app_id, tweak, key);
    }

    /// Decrypts a vector of symbols.
    ///
    /// `m` can be the same slice as `c`.
    /// Any other overlap is not allowed.
    ///
    /// Asserts `m.len == c.len` and `c.len <= max_length`.
    /// Asserts that a `distinct` list has one modulus per symbol.
    pub fn decrypt(
        m: []u16,
        c: []const u16,
        moduli: Moduli,
        app_id: u64,
        tweak: [tweak_length]u8,
        key: [key_length]u8,
    ) (EmptyInputError || SymbolOutOfRangeError)!void {
        return crypt(.decrypt, m, c, moduli, app_id, tweak, key);
    }

    fn crypt(
        comptime direction: Direction,
        dst: []u16,
        src: []const u16,
        moduli: Moduli,
        app_id: u64,
        tweak: [tweak_length]u8,
        key: [key_length]u8,
    ) (EmptyInputError || SymbolOutOfRangeError)!void {
        assert(dst.len == src.len);
        assert(src.len <= max_length);
        if (moduli == .distinct) assert(moduli.distinct.len == src.len);
        if (src.len == 0) return error.EmptyInput;
        for (src, 0..) |symbol, i| {
            if (symbol >= moduli.at(i)) return error.SymbolOutOfRange;
        }

        const n = src.len;
        const split = selectLambda(moduli, n);
        const lambda = split.lambda;
        const q = split.q_lambda;
        const state: ktm.State = .init(key, app_id, domain(moduli, n));

        var x = packX(src[0..lambda], moduli);
        if (lambda < n) {
            const y = dst[lambda..];
            if (y.ptr != src[lambda..].ptr) @memcpy(y, src[lambda..]);
            const y_moduli = moduli.from(lambda);
            const tweaked = state.withTweak(tweak);

            const layers: [5]u8 = switch (direction) {
                .encrypt => .{ 1, 2, 3, 4, 5 },
                .decrypt => .{ 5, 4, 3, 2, 1 },
            };
            for (layers) |d| {
                if (d % 2 == 1) {
                    // X is full here, so its modulus is in the range ALF-16-t accepts.
                    const alf = Alf.fromAlf16tKeys(q, layerAKeys(tweaked, y, d)) catch unreachable;
                    x = applyCipher(direction, &alf, x);
                } else {
                    var generator = layerBPrng(tweaked, x, d);
                    applyKeystream(direction, &generator, y, y_moduli);
                }
            }
        } else if (q > 1) {
            const alf = Alf.fromState(state, tweak, q) catch unreachable;
            x = applyCipher(direction, &alf, x);
        }
        unpackX(dst[0..lambda], x, moduli);
    }
};

fn packX(symbols: []const u16, moduli: AlfL.Moduli) u160 {
    var x: u160 = 0;
    for (symbols, 0..) |symbol, i| x = x * moduli.at(i) + symbol;
    return x;
}

fn unpackX(symbols: []u16, x_packed: u160, moduli: AlfL.Moduli) void {
    var x = x_packed;
    var end = symbols.len;
    while (end != 0) {
        // Handle the trailing symbols that fit in 32 bits together,
        // so that X is divided once per group and not once per symbol.
        var start = end;
        var group_modulus: u64 = 1;
        while (start != 0) : (start -= 1) {
            const next = group_modulus * moduli.at(start - 1);
            if (next > 1 << 32) break;
            group_modulus = next;
        }
        var group = divRem(&x, group_modulus);

        var i = end;
        while (i != start) {
            i -= 1;
            const q = moduli.at(i);
            symbols[i] = @intCast(group % q);
            group /= q;
        }
        end = start;
    }
}

// Divides `x` by `divisor` in place and returns the remainder.
// The divisor is at most 2^32.
// A plain 160-bit division is several times slower.
fn divRem(x: *u160, divisor: u64) u64 {
    var rem: u64 = 0;
    var quotient: u160 = 0;
    comptime var shift = 128;
    inline while (shift >= 0) : (shift -= 32) {
        const cur = (rem << 32) | @as(u32, @truncate(x.* >> shift));
        quotient |= @as(u160, cur / divisor) << shift;
        rem = cur % divisor;
    }
    x.* = quotient;
    return rem;
}

fn domain(moduli: AlfL.Moduli, n: usize) ktm.Domain {
    if (n == 1) return .{ .integer = moduli.at(0) };
    return switch (moduli) {
        .same => |q| .{ .same = .{ .n = @intCast(n), .q = q } },
        .distinct => |qs| .{ .distinct = qs },
    };
}

// Returns the round keys for encrypting X, bound to the current Y.
fn layerAKeys(tweaked: ktm.State, y: []const u16, d: u8) [alf_16t.rounds]AesBlock {
    var state = tweaked;
    state.update(.fromBytes(&ktm.one_star));
    state.compress(y);
    var round_keys: [alf_16t.rounds]AesBlock = undefined;
    state.deriveRoundKeys(&round_keys, 16, d);
    return round_keys;
}

// Returns the keystream generator for masking Y, bound to the current X.
fn layerBPrng(tweaked: ktm.State, x: u160, d: u8) ModPrng {
    var x_low: [16]u8 = undefined;
    mem.writeInt(u128, &x_low, @truncate(x), .little);
    var state = tweaked;
    state.update(.fromBytes(&x_low));

    const x_high: u32 = @intCast(x >> 128);
    var f: [3]ktm.State = undefined;
    for (&f, 1..) |*out, c| out.* = state.initFinal((x_high << 16) | (@as(u32, d) << 8) | @as(u32, @intCast(c)));

    // The paper leaves out the first block of the first two outputs.
    return .init(.{ f[0].a2, f[0].a3, f[1].a2, f[1].a3, f[2].a1, f[2].a2, f[2].a3 });
}

fn applyCipher(comptime direction: Direction, alf: *const Alf, x: u160) u160 {
    return (if (direction == .encrypt) alf.encrypt(x) else alf.decrypt(x)) catch unreachable;
}

fn applyKeystream(comptime direction: Direction, generator: *ModPrng, y: []u16, moduli: AlfL.Moduli) void {
    const block_length = ModPrng.block_length;
    var shared: [block_length]u16 = undefined;
    if (moduli == .same) @memset(&shared, moduli.same);

    var i: usize = 0;
    while (i < y.len) : (i += block_length) {
        const count = @min(block_length, y.len - i);
        const qs = switch (moduli) {
            .same => shared[0..count],
            .distinct => |all| all[i..][0..count],
        };
        var samples: [block_length]u16 = undefined;
        generator.fill(samples[0..count], qs);
        for (y[i..][0..count], samples[0..count], qs) |*symbol, sample, q16| {
            const q = prng.fullModulus(q16);
            symbol.* = @intCast(switch (direction) {
                .encrypt => (@as(u32, symbol.*) + sample) % q,
                .decrypt => (@as(u32, symbol.*) + q - sample) % q,
            });
        }
    }
}

const testing = std.testing;

const test_key: [AlfL.key_length]u8 = @splat(0xa5);
const test_tweak: [AlfL.tweak_length]u8 = @splat(0x5a);

test "AlfL - selectLambda fills X up to 2^144" {
    const Split = AlfL.Split;
    const full = AlfL.max_packed_modulus;

    try testing.expectEqual(Split{ .lambda = 9, .q_lambda = full }, AlfL.selectLambda(.{ .same = 0 }, 256));
    try testing.expectEqual(Split{ .lambda = 16, .q_lambda = 10_000_000_000_000_000 }, AlfL.selectLambda(.{ .same = 10 }, 16));

    // Moduli of 1 take no room, so they still fit once X is full.
    const qs = [_]u16{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 1 };
    try testing.expectEqual(Split{ .lambda = 11, .q_lambda = full }, AlfL.selectLambda(.{ .distinct = &qs }, qs.len));
}

test "AlfL - separate buffers, and same versus distinct moduli" {
    const m: [40]u16 = @splat(5);
    const qs: [40]u16 = @splat(26);

    var separate: [m.len]u16 = undefined;
    var in_place = m;
    try AlfL.encrypt(&separate, &m, .{ .same = 26 }, 0, test_tweak, test_key);
    try AlfL.encrypt(&in_place, &in_place, .{ .same = 26 }, 0, test_tweak, test_key);
    try testing.expectEqualSlices(u16, &separate, &in_place);

    var m2: [m.len]u16 = undefined;
    try AlfL.decrypt(&m2, &separate, .{ .same = 26 }, 0, test_tweak, test_key);
    try testing.expectEqualSlices(u16, &m, &m2);

    var distinct: [m.len]u16 = undefined;
    try AlfL.encrypt(&distinct, &m, .{ .distinct = &qs }, 0, test_tweak, test_key);
    try testing.expect(!mem.eql(u16, &separate, &distinct));
}

test "AlfL - invalid inputs are rejected" {
    var out: [3]u16 = undefined;
    try testing.expectError(error.EmptyInput, AlfL.encrypt(out[0..0], &.{}, .{ .same = 10 }, 0, test_tweak, test_key));
    try testing.expectError(error.SymbolOutOfRange, AlfL.encrypt(&out, &.{ 1, 10, 3 }, .{ .same = 10 }, 0, test_tweak, test_key));
    try testing.expectError(error.SymbolOutOfRange, AlfL.decrypt(&out, &.{ 1, 2, 3 }, .{ .distinct = &.{ 10, 2, 10 } }, 0, test_tweak, test_key));
}
