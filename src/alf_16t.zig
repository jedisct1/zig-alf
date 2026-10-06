//! ALF-16-t: a block cipher on (128 + t) bits, with t in [0, 16].
//! It also encrypts integers modulo any q in (2^127, 2^144].
//!
//! Twelve AES rounds work on the low 128 bits.
//! The t extra bits are kept in a 16-bit register E,
//! which is mixed with the first two columns of the AES state at every round.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;

const errors = @import("errors.zig");
const ModulusOutOfRangeError = errors.ModulusOutOfRangeError;
const ValueOutOfRangeError = errors.ValueOutOfRangeError;

/// The number of rounds, which is also the number of round keys.
pub const rounds = 12;

/// The number of rounds between two range checks when encrypting an integer.
pub const rounds_per_check = 2;

comptime {
    assert(rounds % rounds_per_check == 0);
}

/// ALF-16-t, where a block is made of 16 bytes followed by `t` bits.
pub fn Alf16t(comptime t: u5) type {
    comptime assert(t <= 16); // t must be in [0, 16]

    return struct {
        /// The size of a block in bits.
        pub const block_bits = 128 + @as(usize, t);
        /// The number of bytes a block is stored in.
        pub const block_length = @divCeil(block_bits, 8);

        // The 128-bit register X and the t-bit register E.
        const State = struct { x: AesBlock, e: u16 };

        const e_mask = math.maxInt(@Int(.unsigned, t));

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
        /// `q` must be in (2^127, 2^`block_bits`].
        pub fn encryptInt(m: u160, q: u160, round_keys: *const [rounds]AesBlock) (ModulusOutOfRangeError || ValueOutOfRangeError)!u160 {
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
        pub fn decryptInt(c: u160, q: u160, dec_round_keys: *const [rounds]AesBlock) (ModulusOutOfRangeError || ValueOutOfRangeError)!u160 {
            try checkModulus(q);
            if (c >= q) return error.ValueOutOfRange;

            var state = fromInt(c);
            state.x = aux(state.x);
            var i: usize = rounds;
            while (i != 0) {
                i -= rounds_per_check;
                const group = dec_round_keys[i..][0..rounds_per_check];
                while (true) {
                    state = decryptRounds(state, group);
                    // The final step is only needed to read the value.
                    // X keeps its internal form until the last pair of rounds is done.
                    if (toInt(.{ .x = srf(state.x), .e = state.e }) < q) break;
                }
            }
            state.x = srf(state.x);
            return toInt(state);
        }

        fn checkModulus(q: u160) ModulusOutOfRangeError!void {
            if (q <= 1 << 127 or q > 1 << block_bits) return error.ModulusOutOfRange;
        }

        fn load(src: *const [block_length]u8) State {
            return .{
                .x = .fromBytes(src[0..16]),
                .e = mem.readVarInt(u16, src[16..], .little) & e_mask,
            };
        }

        fn store(dst: *[block_length]u8, state: State) void {
            var e_bytes: [2]u8 = undefined;
            mem.writeInt(u16, &e_bytes, state.e, .little);
            dst[0..16].* = state.x.toBytes();
            dst[16..].* = e_bytes[0 .. block_length - 16].*;
        }

        fn fromInt(v: u160) State {
            var x_bytes: [16]u8 = undefined;
            mem.writeInt(u128, &x_bytes, @truncate(v), .little);
            return .{ .x = .fromBytes(&x_bytes), .e = @intCast(v >> 128) };
        }

        fn toInt(state: State) u160 {
            const x = mem.readInt(u128, &state.x.toBytes(), .little);
            return x | (@as(u160, state.e) << 128);
        }

        // Runs one encryption round per key.
        fn encryptRounds(state: State, round_keys: []const AesBlock) State {
            var x = state.x;
            var e = state.e;
            for (round_keys) |round_key| {
                const u = x.encrypt(round_key);
                x = u.xorBlocks(broadcast(e));
                if (t != 0) e = (e ^ columnParity(u)) & e_mask;
            }
            return .{ .x = x, .e = e };
        }

        // Runs one decryption round per key, last key first.
        // `aux` must have been applied to `state.x` before the first call.
        fn decryptRounds(state: State, dec_round_keys: []const AesBlock) State {
            const zero: AesBlock = .fromBytes(&@splat(0));
            var x = state.x;
            var e = state.e;
            var i = dec_round_keys.len;
            while (i != 0) {
                i -= 1;
                x = x.decrypt(zero);
                if (t != 0) e = (e ^ columnParity(x)) & e_mask;
                x = x.xorBlocks(dec_round_keys[i]).xorBlocks(broadcast(e));
            }
            return .{ .x = x, .e = e };
        }
    };
}

/// Turns encryption round keys into decryption round keys.
pub fn invertRoundKeys(round_keys: [rounds]AesBlock) [rounds]AesBlock {
    var dec_round_keys: [rounds]AesBlock = undefined;
    for (&dec_round_keys, round_keys) |*dec_round_key, round_key| dec_round_key.* = round_key.invMixColumns();
    return dec_round_keys;
}

// The two bytes of E, each repeated over one of the first two columns.
fn broadcast(e: u16) AesBlock {
    var bytes: [16]u8 = @splat(0);
    @memset(bytes[0..4], @truncate(e));
    @memset(bytes[4..8], @truncate(e >> 8));
    return .fromBytes(&bytes);
}

// XOR of the four bytes of each of the first two columns.
fn columnParity(u: AesBlock) u16 {
    const bytes = u.toBytes();
    const p0 = bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3];
    const p1 = bytes[4] ^ bytes[5] ^ bytes[6] ^ bytes[7];
    return (@as(u16, p1) << 8) | p0;
}

// Extra step needed once before the decryption rounds.
fn aux(x: AesBlock) AesBlock {
    return x.encryptLast(.fromBytes(&@splat(0)));
}

// Final step that recovers the plaintext bytes after the decryption rounds.
fn srf(x: AesBlock) AesBlock {
    return x.decryptLast(.fromBytes(&@splat(0)));
}

const testing = std.testing;

test "Alf16t - a block is encrypted like an integer below 2^block_bits" {
    var round_keys: [rounds]AesBlock = undefined;
    for (&round_keys, 0..) |*round_key, r| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = @truncate(23 * r + 5 * i + 13);
        round_key.* = .fromBytes(&bytes);
    }
    const dec_round_keys = invertRoundKeys(round_keys);

    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();

    // One variant for each block length.
    inline for (.{ 0, 5, 16 }) |t| {
        const Variant = Alf16t(t);
        const Int = @Int(.unsigned, 8 * Variant.block_length);
        const q = 1 << Variant.block_bits;
        const m_int = random.uintLessThan(u160, q);

        var m: [Variant.block_length]u8 = undefined;
        mem.writeInt(Int, &m, @intCast(m_int), .little);
        var c: [Variant.block_length]u8 = undefined;
        Variant.encrypt(&c, &m, &round_keys);
        try testing.expectEqual(try Variant.encryptInt(m_int, q, &round_keys), mem.readInt(Int, &c, .little));

        var m2: [Variant.block_length]u8 = undefined;
        Variant.decrypt(&m2, &c, &dec_round_keys);
        try testing.expectEqualSlices(u8, &m, &m2);
    }
}
