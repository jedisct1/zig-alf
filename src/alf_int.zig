//! ALF on one integer in [0, q), for any q in [2, 2^144].
//!
//! The variant depends on the size of q:
//! ALF-0 up to 2^8, ALF-1-t up to 2^15, ALF-n-t up to 2^127 and ALF-16-t above that.

const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const AesBlock = crypto.core.aes.Block;

const alf_16t = @import("alf_16t.zig");
const alf_nt = @import("alf_nt.zig");
const alf_small = @import("alf_small.zig");
const errors = @import("errors.zig");
const ktm = @import("ktm.zig");
const Alf0 = alf_small.Alf0;
const Alf1t = alf_small.Alf1t;
const AlfNt = alf_nt.AlfNt;
const Alf16t = alf_16t.Alf16t;
const ModulusOutOfRangeError = errors.ModulusOutOfRangeError;
const ValueOutOfRangeError = errors.ValueOutOfRangeError;

// The round count of ALF-1-t does not depend on t.
const alf_1t_rounds = Alf1t(1).rounds;

const Direction = enum { encrypt, decrypt };

/// A cipher on the integers in [0, q), for any q in [2, 2^144].
pub const Alf = union(enum) {
    pub const key_length = ktm.key_length;
    pub const tweak_length = ktm.tweak_length;
    /// The largest modulus.
    pub const max_modulus = 1 << 144;

    alf_0: Alf0,
    alf_1t: struct {
        t: u3,
        q: u16,
        round_keys: [alf_1t_rounds]u8,
    },
    alf_nt: struct {
        shape: alf_nt.Shape,
        q: u128,
        enc_keys: [alf_nt.max_rounds]AesBlock,
        dec_keys: [alf_nt.max_rounds]AesBlock,
    },
    alf_16t: struct {
        t: u5,
        q: u160,
        enc_keys: [alf_16t.rounds]AesBlock,
        dec_keys: [alf_16t.rounds]AesBlock,
    },

    /// Sets up the cipher for the integers in [0, q).
    /// `q` must be in [2, `max_modulus`].
    pub fn init(key: [key_length]u8, tweak: [tweak_length]u8, app_id: u64, q: u160) ModulusOutOfRangeError!Alf {
        if (q < 2 or q > max_modulus) return error.ModulusOutOfRange;
        return fromState(.init(key, app_id, .{ .same = .{ .n = 1, .q = q } }), tweak, q);
    }

    /// Same as `init`, with a key state the caller already has.
    /// The vector interface uses this when a whole vector packs into one integer.
    pub fn fromState(state: ktm.State, tweak: [tweak_length]u8, q: u160) ModulusOutOfRangeError!Alf {
        if (q < 2 or q > max_modulus) return error.ModulusOutOfRange;
        const tweaked = state.withTweak(tweak);

        if (q <= 1 << 8) {
            var round_keys: [Alf0.rounds]u8 = undefined;
            tweaked.deriveBytes(&round_keys, 0);
            return .{ .alf_0 = Alf0.init(@intCast(q), round_keys) catch unreachable };
        }
        if (q <= 1 << 15) {
            var round_keys: [alf_1t_rounds]u8 = undefined;
            tweaked.deriveBytes(&round_keys, 0);
            const t = math.log2_int_ceil(u160, q) - 8;
            return .{ .alf_1t = .{ .t = @intCast(t), .q = @intCast(q), .round_keys = round_keys } };
        }
        if (q <= 1 << 127) {
            const shape = alf_nt.Shape.fromModulus(@intCast(q)).?;
            const rounds = shape.rounds();
            var enc_keys: [alf_nt.max_rounds]AesBlock = undefined;
            var dec_keys: [alf_nt.max_rounds]AesBlock = undefined;
            tweaked.deriveRoundKeys(enc_keys[0..rounds], shape.n, 0);
            switch (shape.n) {
                inline 2...15 => |n| alf_nt.invertRoundKeys(n, dec_keys[0..rounds], enc_keys[0..rounds]),
                else => unreachable,
            }
            return .{ .alf_nt = .{ .shape = shape, .q = @intCast(q), .enc_keys = enc_keys, .dec_keys = dec_keys } };
        }
        var round_keys: [alf_16t.rounds]AesBlock = undefined;
        tweaked.deriveRoundKeys(&round_keys, 16, 0);
        return fromAlf16tKeys(q, round_keys);
    }

    /// ALF-16-t with round keys the caller derived, for q in (2^127, 2^144].
    pub fn fromAlf16tKeys(q: u160, round_keys: [alf_16t.rounds]AesBlock) ModulusOutOfRangeError!Alf {
        if (q <= 1 << 127 or q > max_modulus) return error.ModulusOutOfRange;
        const t = math.log2_int_ceil(u160, q) - 128;
        return .{ .alf_16t = .{
            .t = @intCast(t),
            .q = q,
            .enc_keys = round_keys,
            .dec_keys = alf_16t.invertRoundKeys(round_keys),
        } };
    }

    /// Returns the modulus q.
    pub fn modulus(alf: *const Alf) u160 {
        return switch (alf.*) {
            inline else => |*variant| variant.q,
        };
    }

    /// Encrypts an integer in [0, q) into another integer in [0, q).
    pub fn encrypt(alf: *const Alf, m: u160) ValueOutOfRangeError!u160 {
        return alf.crypt(.encrypt, m);
    }

    /// Decrypts an integer in [0, q) into another integer in [0, q).
    pub fn decrypt(alf: *const Alf, c: u160) ValueOutOfRangeError!u160 {
        return alf.crypt(.decrypt, c);
    }

    fn crypt(alf: *const Alf, comptime direction: Direction, x: u160) ValueOutOfRangeError!u160 {
        if (x >= alf.modulus()) return error.ValueOutOfRange;
        const encrypting = direction == .encrypt;
        switch (alf.*) {
            .alf_0 => |*variant| return if (encrypting) variant.encrypt(@intCast(x)) else variant.decrypt(@intCast(x)),
            .alf_1t => |*variant| switch (variant.t) {
                inline 1...7 => |t| {
                    const Variant = Alf1t(t);
                    const op = if (encrypting) Variant.encryptInt else Variant.decryptInt;
                    return op(@intCast(x), variant.q, &variant.round_keys) catch unreachable;
                },
                0 => unreachable,
            },
            .alf_nt => |*variant| switch (variant.shape.n) {
                inline 2...15 => |n| switch (variant.shape.t) {
                    inline else => |t| {
                        const Variant = AlfNt(n, t);
                        const op = if (encrypting) Variant.encryptInt else Variant.decryptInt;
                        const keys = if (encrypting) &variant.enc_keys else &variant.dec_keys;
                        return op(@intCast(x), variant.q, keys[0..Variant.rounds]) catch unreachable;
                    },
                },
                else => unreachable,
            },
            .alf_16t => |*variant| switch (variant.t) {
                inline 0...16 => |t| {
                    const Variant = Alf16t(t);
                    const op = if (encrypting) Variant.encryptInt else Variant.decryptInt;
                    const keys = if (encrypting) &variant.enc_keys else &variant.dec_keys;
                    return op(x, variant.q, keys) catch unreachable;
                },
                else => unreachable,
            },
        }
    }
};

const testing = std.testing;

test "Alf - round trip at every bit width" {
    const key: [Alf.key_length]u8 = @splat(0x5a);
    const tweak: [Alf.tweak_length]u8 = @splat(0xa5);
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();

    // For each width, a power of two and a modulus that is not one.
    for (1..145) |width| {
        const full = @as(u160, 1) << @intCast(width);
        for ([_]u160{ full, full - full / 3 }) |q| {
            const alf: Alf = try .init(key, tweak, width, q);
            for (0..8) |_| {
                const m = random.uintLessThan(u160, q);
                const c = try alf.encrypt(m);
                try testing.expect(c < q);
                try testing.expectEqual(m, try alf.decrypt(c));
            }
        }
    }
}

test "Alf - invalid moduli and values are rejected" {
    const key: [Alf.key_length]u8 = @splat(1);
    try testing.expectError(error.ModulusOutOfRange, Alf.init(key, key, 0, 1));
    try testing.expectError(error.ModulusOutOfRange, Alf.init(key, key, 0, Alf.max_modulus + 1));
    try testing.expectError(error.ModulusOutOfRange, Alf.fromAlf16tKeys(1 << 127, undefined));
    const alf: Alf = try .init(key, key, 0, 1000);
    try testing.expectError(error.ValueOutOfRange, alf.encrypt(1000));
    try testing.expectError(error.ValueOutOfRange, alf.decrypt(1000));
}
