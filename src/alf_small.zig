//! ALF-0 and ALF-1-t, the ALF variants for small domains (Appendix F of the ALF paper).
//!
//! * ALF-0 handles q in [2, 256] with a secret S-box derived from the key.
//! * ALF-1-t handles 9 to 15 bits, so q in (2^8, 2^15].

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const AesBlock = crypto.core.aes.Block;

const errors = @import("errors.zig");
const ModulusOutOfRangeError = errors.ModulusOutOfRangeError;
const ValueOutOfRangeError = errors.ValueOutOfRangeError;

/// ALF-0: a secret permutation of [0, q), for q in [2, 256].
pub const Alf0 = struct {
    /// The number of round keys, of one byte each.
    pub const rounds = 32;

    q: u16,
    // Only the first q entries of each table are meaningful.
    enc_table: [256]u8,
    dec_table: [256]u8,

    pub fn init(q: u16, round_keys: [rounds]u8) ModulusOutOfRangeError!Alf0 {
        if (q < 2 or q > 256) return error.ModulusOutOfRange;

        var enc_table: [256]u8 = @splat(0);
        var dec_table: [256]u8 = @splat(0);
        var count: usize = 0;
        for (permutation(round_keys)) |v| {
            if (v >= q) continue;
            enc_table[count] = v;
            dec_table[v] = @intCast(count);
            count += 1;
        }
        assert(count == q);
        return .{ .q = q, .enc_table = enc_table, .dec_table = dec_table };
    }

    /// Encrypts an integer in [0, q).
    /// Asserts `m < q`.
    pub fn encrypt(alf: Alf0, m: u8) u8 {
        assert(m < alf.q);
        return alf.enc_table[m];
    }

    /// Decrypts an integer in [0, q).
    /// Asserts `c < q`.
    pub fn decrypt(alf: Alf0, c: u8) u8 {
        assert(c < alf.q);
        return alf.dec_table[c];
    }

    // Builds the secret permutation of all 256 byte values.
    //
    // Each `aesenclast` call also moves bytes around, and four calls bring them back in place.
    // The round count is a multiple of four, so every byte ends up where it started.
    fn permutation(round_keys: [rounds]u8) [256]u8 {
        var s256: [256]u8 = undefined;
        for (0..16) |k| {
            var bytes: [16]u8 = undefined;
            for (&bytes, 16 * k..) |*byte, v| byte.* = @intCast(v);
            var x: AesBlock = .fromBytes(&bytes);
            for (round_keys) |round_key| x = x.encryptLast(.fromBytes(&@splat(round_key)));
            s256[16 * k ..][0..16].* = x.toBytes();
        }
        return s256;
    }
};

/// ALF-1-t: a cipher on integers of (8 + t) bits, with `t` in [1, 7].
pub fn Alf1t(comptime t: u3) type {
    comptime assert(t != 0); // t must be in [1, 7]

    return struct {
        /// The size of a block in bits.
        pub const block_bits = 8 + @as(usize, t);
        /// The number of rounds, which is also the number of round keys, of one byte each.
        pub const rounds = 48;
        /// The number of rounds between two range checks.
        pub const rounds_per_check = 2;

        // The low byte X of a block and its t high bits E.
        const State = struct { x: u8, e: u8 };

        const e_mask = math.maxInt(@Int(.unsigned, t));

        comptime {
            assert(rounds % rounds_per_check == 0);
        }

        /// Encrypts an integer in [0, q) into another integer in [0, q).
        /// `q` must be in (2^8, 2^`block_bits`].
        pub fn encryptInt(m: u16, q: u16, round_keys: *const [rounds]u8) (ModulusOutOfRangeError || ValueOutOfRangeError)!u16 {
            try checkModulus(q);
            if (m >= q) return error.ValueOutOfRange;

            var state = fromInt(m);
            var i: usize = 0;
            while (i < rounds) : (i += rounds_per_check) {
                const group = round_keys[i..][0..rounds_per_check];
                while (true) {
                    for (group) |round_key| state = encryptRound(state, round_key);
                    if (toInt(state) < q) break;
                }
            }
            return toInt(state);
        }

        /// Decrypts an integer in [0, q) into another integer in [0, q).
        pub fn decryptInt(c: u16, q: u16, round_keys: *const [rounds]u8) (ModulusOutOfRangeError || ValueOutOfRangeError)!u16 {
            try checkModulus(q);
            if (c >= q) return error.ValueOutOfRange;

            var state = fromInt(c);
            var i: usize = rounds;
            while (i != 0) {
                i -= rounds_per_check;
                const group = round_keys[i..][0..rounds_per_check];
                while (true) {
                    var j: usize = group.len;
                    while (j != 0) {
                        j -= 1;
                        state = decryptRound(state, group[j]);
                    }
                    if (toInt(state) < q) break;
                }
            }
            return toInt(state);
        }

        fn checkModulus(q: u16) ModulusOutOfRangeError!void {
            if (q <= 1 << 8 or q > 1 << block_bits) return error.ModulusOutOfRange;
        }

        fn fromInt(v: u16) State {
            return .{ .x = @truncate(v), .e = @intCast(v >> 8) };
        }

        fn toInt(state: State) u16 {
            return (@as(u16, state.e) << 8) | state.x;
        }

        fn encryptRound(state: State, round_key: u8) State {
            const u = sbox(state.x) ^ round_key;
            return .{ .x = u ^ (state.e << 1), .e = (u ^ state.e) & e_mask };
        }

        fn decryptRound(state: State, round_key: u8) State {
            // Bit i of the previous E is the XOR of bits 0..i of X ^ E.
            const a = state.x ^ state.e;
            var prefix: u8 = 0;
            var e: u8 = 0;
            inline for (0..t) |bit| {
                prefix ^= (a >> bit) & 1;
                e |= prefix << bit;
            }
            return .{ .x = invSbox(state.x ^ (e << 1) ^ round_key), .e = e };
        }
    };
}

// The AES S-box, computed with the AES round primitive instead of a table.
fn sbox(byte: u8) u8 {
    const block: AesBlock = .fromBytes(&@splat(byte));
    return block.encryptLast(.fromBytes(&@splat(0))).toBytes()[0];
}

fn invSbox(byte: u8) u8 {
    const block: AesBlock = .fromBytes(&@splat(byte));
    return block.decryptLast(.fromBytes(&@splat(0))).toBytes()[0];
}

const testing = std.testing;

test "Alf0 - is a permutation of [0, q)" {
    var round_keys: [Alf0.rounds]u8 = undefined;
    for (&round_keys, 0..) |*round_key, i| round_key.* = @intCast(i * 7 + 11);

    for ([_]u16{ 100, 256 }) |q| {
        const alf: Alf0 = try .init(q, round_keys);
        var seen: [256]bool = @splat(false);
        for (0..q) |m| {
            const c = alf.encrypt(@intCast(m));
            try testing.expect(c < q and !seen[c]);
            seen[c] = true;
            try testing.expectEqual(m, alf.decrypt(c));
        }
    }
}

test "Alf1t - is a permutation of [0, q)" {
    inline for (.{ .{ 4, 1000 }, .{ 3, 2048 } }) |case| {
        const t, const q = case;
        const Variant = Alf1t(t);
        var round_keys: [Variant.rounds]u8 = undefined;
        for (&round_keys, 0..) |*round_key, i| round_key.* = @truncate(i * 13 + 5);

        var seen: [q]bool = @splat(false);
        for (0..q) |m| {
            const c = try Variant.encryptInt(@intCast(m), q, &round_keys);
            try testing.expect(c < q and !seen[c]);
            seen[c] = true;
            try testing.expectEqual(m, try Variant.decryptInt(c, q, &round_keys));
        }
    }
}
