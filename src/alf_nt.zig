//! ALF-n-t: a block cipher on (8 * n + t) bits, with n in [2, 15] and t in [0, 7].
//! See Algorithms 1 and 2 of the ALF paper.
//!
//! The first n bytes of a block live in a 128-bit register.
//! The remaining t bits sit in the first byte of a second register.
//!
//! The cipher also encrypts integers in [0, q), for any q that fits in a block.
//! Rounds are then applied two at a time.
//! After each pair, if the value is not below q, the same pair is applied again until it is.
//! The paper calls this cycle-sliding.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;

const errors = @import("errors.zig");
const tables = @import("tables.zig");
const ModulusOutOfRangeError = errors.ModulusOutOfRangeError;
const ValueOutOfRangeError = errors.ValueOutOfRangeError;

/// The largest round count of any ALF-n-t variant.
pub const max_rounds = 28;

/// The parameters of an ALF-n-t variant.
pub const Shape = struct {
    n: u4,
    t: u3,

    /// Returns the smallest variant that fits the modulus.
    /// Returns `null` when `q` is too small (use ALF-1-t) or too large (use ALF-16-t).
    pub fn fromModulus(q: u128) ?Shape {
        if (q <= 1 << 15 or q > 1 << 127) return null;
        const bits = math.log2_int_ceil(u128, q);
        return .{ .n = @intCast(bits / 8), .t = @intCast(bits % 8) };
    }
};

/// ALF-n-t, where a block is made of `n` bytes followed by `t` bits.
pub fn AlfNt(comptime n: u4, comptime t: u3) type {
    comptime assert(n >= 2); // n must be in [2, 15]

    return struct {
        /// The size of a block in bits.
        pub const block_bits = 8 * @as(usize, n) + t;
        /// The number of bytes a block is stored in.
        pub const block_length = @divCeil(block_bits, 8);
        /// The number of rounds, which is also the number of round keys.
        pub const rounds = tables.rounds[n - tables.n_min][@intFromBool(t != 0)];
        /// The number of rounds between two range checks when encrypting an integer.
        pub const rounds_per_check = 2;

        // The n-byte register X and the t-bit register E.
        const State = struct { x: AesBlock, e: AesBlock };

        const enc_sigma = &tables.enc_sigma[n - tables.n_min];
        const enc_beta = &tables.enc_beta[n - tables.n_min];
        const dec_alpha = &tables.dec_alpha[n - tables.n_min];
        const dec_beta = &tables.dec_beta[n - tables.n_min];
        const dec_sigma = &tables.dec_sigma[n - tables.n_min];
        const dec_tau = &tables.dec_tau[n - tables.n_min];
        const rho = &tables.rho[n - tables.n_min];

        const x_mask = math.maxInt(@Int(.unsigned, 8 * @as(usize, n)));
        const e_mask = math.maxInt(@Int(.unsigned, t));
        const e_mask_bytes = [_]u8{e_mask} ++ @as([15]u8, @splat(0));

        comptime {
            assert(rounds <= max_rounds);
            assert(rounds % rounds_per_check == 0);
        }

        /// Encrypts a block.
        ///
        /// The unused high bits of the last byte are ignored on input and zero on output.
        pub fn encrypt(dst: *[block_length]u8, src: *const [block_length]u8, round_keys: *const [rounds]AesBlock) void {
            store(dst, encryptRounds(load(src), round_keys));
        }

        /// Decrypts a block.
        /// The keys must come from `invertRoundKeys`.
        pub fn decrypt(dst: *[block_length]u8, src: *const [block_length]u8, dec_round_keys: *const [rounds]AesBlock) void {
            var state = load(src);
            state.x = aux(state.x);
            state = decryptRounds(state, dec_round_keys);
            state.x = srf(state.x);
            store(dst, state);
        }

        /// Encrypts an integer in [0, q) into another integer in [0, q).
        /// `q` must be in (2^15, 2^`block_bits`].
        pub fn encryptInt(m: u128, q: u128, round_keys: *const [rounds]AesBlock) (ModulusOutOfRangeError || ValueOutOfRangeError)!u128 {
            try checkModulus(q);
            if (m >= q) return error.ValueOutOfRange;

            var state = fromInt(m);
            var i: usize = 0;
            while (i < rounds) : (i += rounds_per_check) {
                const group = round_keys[i..][0..rounds_per_check];
                while (true) {
                    state = encryptRounds(state, group);
                    if (toInt(state) < q) break;
                }
            }
            return toInt(state);
        }

        /// Decrypts an integer in [0, q) into another integer in [0, q).
        /// The keys must come from `invertRoundKeys`.
        pub fn decryptInt(c: u128, q: u128, dec_round_keys: *const [rounds]AesBlock) (ModulusOutOfRangeError || ValueOutOfRangeError)!u128 {
            try checkModulus(q);
            if (c >= q) return error.ValueOutOfRange;

            var state = fromInt(c);
            var i: usize = rounds;
            while (i != 0) {
                i -= rounds_per_check;
                const group = dec_round_keys[i..][0..rounds_per_check];
                while (true) {
                    state.x = aux(state.x);
                    state = decryptRounds(state, group);
                    state.x = srf(state.x);
                    if (toInt(state) < q) break;
                }
            }
            return toInt(state);
        }

        /// Turns encryption round keys into decryption round keys.
        pub fn invertRoundKeys(round_keys: [rounds]AesBlock) [rounds]AesBlock {
            const a: AesBlock = .fromBytes(&tables.const_a[n - tables.n_min]);
            var dec_round_keys: [rounds]AesBlock = undefined;
            for (&dec_round_keys, round_keys) |*dec_round_key, round_key| {
                const folded = round_key.xorBlocks(shuffle(round_key, enc_beta));
                dec_round_key.* = a.xorBlocks(shuffle(folded, dec_alpha)).invMixColumns();
            }
            return dec_round_keys;
        }

        fn checkModulus(q: u128) ModulusOutOfRangeError!void {
            if (q <= 1 << 15 or q > 1 << block_bits) return error.ModulusOutOfRange;
        }

        fn load(src: *const [block_length]u8) State {
            var x_bytes: [16]u8 = @splat(0);
            x_bytes[0..n].* = src[0..n].*;
            var e_bytes: [16]u8 = @splat(0);
            if (t != 0) e_bytes[0] = src[n] & e_mask;
            return .{ .x = .fromBytes(&x_bytes), .e = .fromBytes(&e_bytes) };
        }

        fn store(dst: *[block_length]u8, state: State) void {
            dst[0..n].* = state.x.toBytes()[0..n].*;
            if (t != 0) dst[n] = state.e.toBytes()[0];
        }

        fn fromInt(v: u128) State {
            var x_bytes: [16]u8 = undefined;
            mem.writeInt(u128, &x_bytes, v & x_mask, .little);
            var e_bytes: [16]u8 = @splat(0);
            e_bytes[0] = @intCast(v >> (8 * @as(u7, n)));
            return .{ .x = .fromBytes(&x_bytes), .e = .fromBytes(&e_bytes) };
        }

        fn toInt(state: State) u128 {
            const x = mem.readInt(u128, &state.x.toBytes(), .little) & x_mask;
            const e: u128 = state.e.toBytes()[0];
            return x | (e << (8 * @as(u7, n)));
        }

        // Runs one encryption round per key.
        fn encryptRounds(state: State, round_keys: []const AesBlock) State {
            const zero: AesBlock = .fromBytes(&@splat(0));
            var x = state.x;
            var e = state.e;
            for (round_keys) |round_key| {
                const u = shuffle(x, enc_sigma).encrypt(round_key);
                x = u.xorBlocks(shuffle(u, enc_beta)).xorBlocks(shuffle(e, rho));
                if (t != 0) e = updateE(e, u, zero);
            }
            return .{ .x = x, .e = e };
        }

        // Runs one decryption round per key, last key first.
        // `aux` must have been applied to `state.x` before.
        fn decryptRounds(state: State, dec_round_keys: []const AesBlock) State {
            const b: AesBlock = .fromBytes(&([_]u8{tables.parityCompensation(n)} ++ @as([15]u8, @splat(0))));
            var x = state.x;
            var e = state.e;
            var i = dec_round_keys.len;
            while (i != 0) {
                i -= 1;
                const round_key = dec_round_keys[i];
                const w = shuffle(x, dec_sigma).decrypt(round_key);
                if (t != 0) e = updateE(e, w.xorBlocks(round_key), b);
                x = w.xorBlocks(shuffle(w, dec_beta)).xorBlocks(shuffle(e, rho));
            }
            return .{ .x = x, .e = e };
        }

        // Extra step needed once before the decryption rounds.
        fn aux(x: AesBlock) AesBlock {
            return shuffle(x, enc_sigma).encryptLast(.fromBytes(&@splat(0)));
        }

        // Final step that recovers the plaintext bytes after the decryption rounds.
        fn srf(x: AesBlock) AesBlock {
            return shuffle(x, dec_tau).decryptLast(.fromBytes(&@splat(0)));
        }

        // Mixes the parity of the first column of `u` into the t extra bits.
        fn updateE(e: AesBlock, u: AesBlock, b: AesBlock) AesBlock {
            const lanes: @Vector(4, u32) = @bitCast(u.toBytes());
            const fold16 = lanes ^ (lanes >> @splat(16));
            const fold8 = fold16 ^ (fold16 >> @splat(8));
            const parity: AesBlock = .fromBytes(&@bitCast(fold8));
            return e.xorBlocks(b).xorBlocks(parity).andBlocks(.fromBytes(&e_mask_bytes));
        }
    };
}

// Byte shuffle with the PSHUFB convention: a negative control byte gives zero.
fn shuffle(x: AesBlock, comptime ctrl: *const tables.Shuffle) AesBlock {
    // For `@shuffle`, a negative index picks from the second vector, which is all zeros here.
    const mask = comptime mask: {
        var indices: [16]i32 = undefined;
        for (&indices, ctrl) |*index, c| index.* = if (c < 0) -1 else c;
        break :mask indices;
    };
    const src: @Vector(16, u8) = x.toBytes();
    const zeros: @Vector(16, u8) = @splat(0);
    const out: [16]u8 = @shuffle(u8, src, zeros, mask);
    return .fromBytes(&out);
}

const testing = std.testing;

// Any round keys will do for tests that only check that the cipher is a permutation.
fn testRoundKeys(comptime Variant: type) [Variant.rounds]AesBlock {
    var round_keys: [Variant.rounds]AesBlock = undefined;
    for (&round_keys, 0..) |*round_key, r| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = @truncate(7 * r + 3 * i + 1);
        round_key.* = .fromBytes(&bytes);
    }
    return round_keys;
}

test "AlfNt - ALF-11-5 reference vector from Appendix C" {
    const Alf11_5 = AlfNt(11, 5);
    try testing.expectEqual(14, Alf11_5.rounds);

    // Same round keys as the example program in the paper.
    var round_keys: [Alf11_5.rounds]AesBlock = undefined;
    for (&round_keys, 0..) |*round_key, r| {
        var bytes: [16]u8 = @splat(0);
        for (bytes[0..11], 1..) |*byte, i| byte.* = @intCast(16 * r + i);
        round_key.* = .fromBytes(&bytes);
    }

    const m = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x1a };
    const expected = [_]u8{ 0xc4, 0x12, 0x73, 0x4f, 0x64, 0x7a, 0x7d, 0xaa, 0x3f, 0x73, 0x60, 0x13 };

    var c: [Alf11_5.block_length]u8 = undefined;
    Alf11_5.encrypt(&c, &m, &round_keys);
    try testing.expectEqualSlices(u8, &expected, &c);

    var m2: [Alf11_5.block_length]u8 = undefined;
    Alf11_5.decrypt(&m2, &c, &Alf11_5.invertRoundKeys(round_keys));
    try testing.expectEqualSlices(u8, &m, &m2);
}

test "AlfNt - integers map to distinct integers below the modulus" {
    const Alf3_0 = AlfNt(3, 0);
    const q = 50000;
    const round_keys = testRoundKeys(Alf3_0);
    const dec_round_keys = Alf3_0.invertRoundKeys(round_keys);

    var seen: [q]bool = @splat(false);
    for (0..200) |m| {
        const c = try Alf3_0.encryptInt(m, q, &round_keys);
        try testing.expect(c < q and !seen[@intCast(c)]);
        seen[@intCast(c)] = true;
        try testing.expectEqual(m, try Alf3_0.decryptInt(c, q, &dec_round_keys));
    }
}

test "AlfNt - invalid moduli and values are rejected" {
    const Alf3_0 = AlfNt(3, 0);
    const round_keys = testRoundKeys(Alf3_0);
    try testing.expectError(error.ModulusOutOfRange, Alf3_0.encryptInt(0, 1 << 15, &round_keys));
    try testing.expectError(error.ModulusOutOfRange, Alf3_0.decryptInt(0, (1 << 24) + 1, &round_keys));
    try testing.expectError(error.ValueOutOfRange, Alf3_0.encryptInt(1 << 24, 1 << 24, &round_keys));
}

test "Shape.fromModulus picks the smallest variant" {
    try testing.expectEqual(Shape{ .n = 4, .t = 2 }, Shape.fromModulus(10_000_000_000));
    try testing.expectEqual(Shape{ .n = 2, .t = 0 }, Shape.fromModulus((1 << 15) + 1));
    try testing.expectEqual(Shape{ .n = 15, .t = 7 }, Shape.fromModulus(1 << 127));
    try testing.expectEqual(null, Shape.fromModulus(1 << 15));
    try testing.expectEqual(null, Shape.fromModulus((1 << 127) + 1));
}
