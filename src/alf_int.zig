//! ALF on one integer in [0, Q), for any Q in [2, 2^144].
//!
//! The variant depends on the size of Q:
//! ALF-0 up to 2^8, ALF-1-t up to 2^15, ALF-n-t up to 2^127 and ALF-16-t above that.

const std = @import("std");
const ktm = @import("ktm.zig");
const alf_nt = @import("alf_nt.zig");
const fpe = @import("fpe.zig");
const alf_16t = @import("alf_16t.zig");
const alf_0 = @import("alf_small.zig").alf_0;
const alf_1t = @import("alf_small.zig").alf_1t;

const Block = alf_nt.Block;

pub const Error = error{ ModulusOutOfRange, ValueOutOfRange };

pub const max_modulus: u160 = 1 << 144;

const Direction = enum { encrypt, decrypt };

pub const Cipher = union(enum) {
    alf0: alf_0.Cipher,
    alf1t: struct { t: u8, q: u16, round_keys: [alf_1t.rounds]u8 },
    alfnt: struct {
        n: u8,
        t: u8,
        q: u128,
        rounds: u8,
        enc_keys: [alf_nt.max_rounds]Block,
        dec_keys: [alf_nt.max_rounds]Block,
    },
    alf16t: struct {
        t: u8,
        q: u160,
        enc_keys: [alf_16t.rounds]Block,
        dec_keys: [alf_16t.rounds]Block,
    },

    pub fn init(key: [16]u8, tweak: [16]u8, app_id: u64, q: u160) Error!Cipher {
        if (q < 2 or q > max_modulus) return error.ModulusOutOfRange;
        return fromState(ktm.keyInit(key, app_id, .{ .integer = q }), tweak, q);
    }

    /// Same as `init`, with a key state the caller already has.
    /// The vector interface uses this when a whole vector packs into one integer.
    pub fn fromState(state: ktm.State, tweak: [16]u8, q: u160) Error!Cipher {
        if (q < 2 or q > max_modulus) return error.ModulusOutOfRange;
        if (q <= 1 << 8) {
            var round_keys: [alf_0.rounds]u8 = undefined;
            ktm.alf0RoundKeys(state, tweak, &round_keys);
            return .{ .alf0 = alf_0.Cipher.init(@intCast(q), &round_keys) catch unreachable };
        }
        if (q <= 1 << 15) {
            var round_keys: [alf_1t.rounds]u8 = undefined;
            ktm.alf1tRoundKeys(state, tweak, &round_keys);
            const t = std.math.log2_int_ceil(u160, q) - 8;
            return .{ .alf1t = .{ .t = t, .q = @intCast(q), .round_keys = round_keys } };
        }
        if (q <= 1 << 127) {
            const shape = fpe.selectShape(@intCast(q)).?;
            const rounds = alf_nt.roundCount(shape.n, shape.t);
            var enc_keys: [alf_nt.max_rounds]Block = undefined;
            var dec_keys: [alf_nt.max_rounds]Block = undefined;
            ktm.alfNtRoundKeys(shape.n, rounds, state, tweak, enc_keys[0..rounds]);
            switch (shape.n) {
                inline 2...15 => |n| alf_nt.prepareDecryption(n, enc_keys[0..rounds], dec_keys[0..rounds]),
                else => unreachable,
            }
            return .{ .alfnt = .{
                .n = shape.n,
                .t = shape.t,
                .q = @intCast(q),
                .rounds = rounds,
                .enc_keys = enc_keys,
                .dec_keys = dec_keys,
            } };
        }
        var round_keys: [alf_16t.rounds]Block = undefined;
        ktm.alf16tRoundKeys(state, tweak, &round_keys);
        return fromAlf16tKeys(q, round_keys);
    }

    /// ALF-16-t with round keys the caller derived, for q in (2^127, 2^144].
    pub fn fromAlf16tKeys(q: u160, round_keys: [alf_16t.rounds]Block) Error!Cipher {
        if (q <= 1 << 127 or q > max_modulus) return error.ModulusOutOfRange;
        var dec_keys: [alf_16t.rounds]Block = undefined;
        alf_16t.prepareDecryption(&round_keys, &dec_keys);
        const t = std.math.log2_int_ceil(u160, q) - 128;
        return .{ .alf16t = .{ .t = t, .q = q, .enc_keys = round_keys, .dec_keys = dec_keys } };
    }

    pub fn modulus(self: *const Cipher) u160 {
        return switch (self.*) {
            inline else => |*c| c.q,
        };
    }

    pub fn encrypt(self: *const Cipher, x: u160) Error!u160 {
        return self.apply(.encrypt, x);
    }

    pub fn decrypt(self: *const Cipher, x: u160) Error!u160 {
        return self.apply(.decrypt, x);
    }

    fn apply(self: *const Cipher, comptime dir: Direction, x: u160) Error!u160 {
        if (x >= self.modulus()) return error.ValueOutOfRange;
        const encrypting = dir == .encrypt;
        switch (self.*) {
            .alf0 => |*c| return if (encrypting) c.encrypt(@intCast(x)) else c.decrypt(@intCast(x)),
            .alf1t => |*c| {
                const op = if (encrypting) alf_1t.encrypt else alf_1t.decrypt;
                switch (c.t) {
                    inline 1...7 => |t| return op(t, c.q, &c.round_keys, @intCast(x)) catch unreachable,
                    else => unreachable,
                }
            },
            .alfnt => |*c| {
                const op = if (encrypting) fpe.encryptInt else fpe.decryptInt;
                const keys = (if (encrypting) &c.enc_keys else &c.dec_keys)[0..c.rounds];
                switch (c.n) {
                    inline 2...15 => |n| switch (c.t) {
                        inline 0...7 => |t| return op(n, t, c.q, keys, @intCast(x)) catch unreachable,
                        else => unreachable,
                    },
                    else => unreachable,
                }
            },
            .alf16t => |*c| {
                const op = if (encrypting) alf_16t.encryptInt else alf_16t.decryptInt;
                const keys = if (encrypting) &c.enc_keys else &c.dec_keys;
                switch (c.t) {
                    inline 0...16 => |t| return op(t, c.q, keys, x) catch unreachable,
                    else => unreachable,
                }
            },
        }
    }
};

test "round trip at every bit width" {
    const key: [16]u8 = @splat(0x5a);
    const tweak: [16]u8 = @splat(0xa5);
    var rng = std.Random.DefaultPrng.init(1);
    const rand = rng.random();

    // For each width, a power of two and a modulus that is not one.
    for (1..145) |width| {
        const full = @as(u160, 1) << @intCast(width);
        for ([_]u160{ full, full - full / 3 }) |q| {
            const cipher: Cipher = try .init(key, tweak, width, q);
            for (0..8) |_| {
                const x = rand.uintLessThan(u160, q);
                const y = try cipher.encrypt(x);
                try std.testing.expect(y < q);
                try std.testing.expectEqual(x, try cipher.decrypt(y));
            }
        }
    }
}

test "invalid moduli and values are rejected" {
    const key: [16]u8 = @splat(1);
    try std.testing.expectError(error.ModulusOutOfRange, Cipher.init(key, key, 0, 1));
    try std.testing.expectError(error.ModulusOutOfRange, Cipher.init(key, key, 0, max_modulus + 1));
    try std.testing.expectError(error.ModulusOutOfRange, Cipher.fromAlf16tKeys(1 << 127, undefined));
    const cipher: Cipher = try .init(key, key, 0, 1000);
    try std.testing.expectError(error.ValueOutOfRange, cipher.encrypt(1000));
    try std.testing.expectError(error.ValueOutOfRange, cipher.decrypt(1000));
}
