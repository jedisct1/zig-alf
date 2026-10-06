//! ALF-0 and ALF-1-t, the ALF variants for small domains (Appendix F of the ALF paper).
//!
//! * ALF-0 handles Q in [2, 256] with a secret S-box derived from the key.
//! * ALF-1-t handles 9 to 15 bits, so Q in (2^8, 2^15].

const std = @import("std");
const aes_core = std.crypto.core.aes;

const Block = aes_core.Block;

/// AES S-box of one byte, computed with the AES round primitive instead of a table.
pub fn rijndaelSbox(byte: u8) u8 {
    const zero_bytes: [16]u8 = @splat(0);
    const byte_bytes: [16]u8 = @splat(byte);
    return Block.fromBytes(&byte_bytes).encryptLast(Block.fromBytes(&zero_bytes)).toBytes()[0];
}

pub fn rijndaelInvSbox(byte: u8) u8 {
    const zero_bytes: [16]u8 = @splat(0);
    const byte_bytes: [16]u8 = @splat(byte);
    return Block.fromBytes(&byte_bytes).decryptLast(Block.fromBytes(&zero_bytes)).toBytes()[0];
}

pub const alf_0 = struct {
    pub const rounds = 32;

    pub const Error = error{ModulusOutOfRange};

    /// Secret permutation of [0, q), for q in [2, 256].
    /// Only the first q entries of each table are meaningful.
    pub const Cipher = struct {
        q: u16,
        enc_table: [256]u8,
        dec_table: [256]u8,

        pub fn init(q: u16, round_keys: *const [rounds]u8) Error!Cipher {
            if (q < 2 or q > 256) return error.ModulusOutOfRange;
            const s256 = computeS256(round_keys.*);

            var enc_table: [256]u8 = @splat(0);
            var dec_table: [256]u8 = @splat(0);
            var j: usize = 0;
            for (s256) |v| {
                if (v < q) {
                    enc_table[j] = v;
                    dec_table[v] = @intCast(j);
                    j += 1;
                }
            }
            std.debug.assert(j == q);
            return .{ .q = q, .enc_table = enc_table, .dec_table = dec_table };
        }

        pub fn encrypt(self: Cipher, plaintext: u8) u8 {
            std.debug.assert(plaintext < self.q);
            return self.enc_table[plaintext];
        }

        pub fn decrypt(self: Cipher, ciphertext: u8) u8 {
            std.debug.assert(ciphertext < self.q);
            return self.dec_table[ciphertext];
        }
    };

    /// Build the secret permutation of all 256 byte values.
    ///
    /// Each `aesenclast` call also moves bytes around, and four calls bring them back in place.
    /// The round count is a multiple of four, so every byte ends up where it started.
    fn computeS256(round_keys: [rounds]u8) [256]u8 {
        var s256: [256]u8 = undefined;
        for (0..16) |k| {
            var x_bytes: [16]u8 = undefined;
            for (0..16) |i| x_bytes[i] = @intCast(16 * k + i);
            var x = Block.fromBytes(&x_bytes);
            for (round_keys) |rk_byte| {
                const rk_bytes: [16]u8 = @splat(rk_byte);
                x = x.encryptLast(Block.fromBytes(&rk_bytes));
            }
            const out = x.toBytes();
            for (0..16) |i| s256[16 * k + i] = out[i];
        }
        return s256;
    }
};

pub const alf_1t = struct {
    pub const rounds = 48;
    pub const k_group = 2;

    pub const Error = error{ ModulusOutOfRange, ValueOutOfRange };

    pub fn validate(comptime t: u8) void {
        comptime if (t < 1 or t > 7) @compileError("ALF-1-t requires t in [1, 7]");
    }

    fn mask(comptime t: u8) u8 {
        return (@as(u8, 1) << t) - 1;
    }

    /// One encryption round.
    fn forwardRound(comptime t: u8, x: *u8, e: *u8, rk: u8) void {
        const u = rijndaelSbox(x.*) ^ rk;
        x.* = u ^ (e.* << 1);
        e.* = (u ^ e.*) & mask(t);
    }

    /// One decryption round.
    fn reverseRound(comptime t: u8, x: *u8, e: *u8, rk: u8) void {
        // Bit i of the previous E is the XOR of bits 0..i of X ^ E.
        const a = x.* ^ e.*;
        var prefix: u8 = 0;
        var new_e: u8 = 0;
        var bit: u3 = 0;
        while (bit < t) : (bit += 1) {
            prefix ^= (a >> bit) & 1;
            new_e |= prefix << bit;
        }
        e.* = new_e;
        x.* = rijndaelInvSbox(x.* ^ (e.* << 1) ^ rk);
    }

    /// Encrypt a value in [0, q), for q in (2^8, 2^(8 + t)].
    pub fn encrypt(
        comptime t: u8,
        q: u16,
        round_keys: *const [rounds]u8,
        plaintext: u16,
    ) Error!u16 {
        comptime validate(t);
        if (q <= 0x100 or q > @as(u16, 1) << (8 + t)) return error.ModulusOutOfRange;
        if (plaintext >= q) return error.ValueOutOfRange;

        var x: u8 = @truncate(plaintext);
        var e: u8 = @intCast(plaintext >> 8);

        var i: usize = 0;
        while (i < rounds / k_group) : (i += 1) {
            while (true) {
                var j: usize = 0;
                while (j < k_group) : (j += 1) {
                    forwardRound(t, &x, &e, round_keys[k_group * i + j]);
                }
                if ((@as(u16, e) << 8) + x < q) break;
            }
        }
        return (@as(u16, e) << 8) + x;
    }

    /// Inverse of `encrypt`.
    pub fn decrypt(
        comptime t: u8,
        q: u16,
        round_keys: *const [rounds]u8,
        ciphertext: u16,
    ) Error!u16 {
        comptime validate(t);
        if (q <= 0x100 or q > @as(u16, 1) << (8 + t)) return error.ModulusOutOfRange;
        if (ciphertext >= q) return error.ValueOutOfRange;

        var x: u8 = @truncate(ciphertext);
        var e: u8 = @intCast(ciphertext >> 8);

        var i: usize = rounds / k_group;
        while (i > 0) {
            i -= 1;
            while (true) {
                var j: usize = k_group;
                while (j > 0) {
                    j -= 1;
                    reverseRound(t, &x, &e, round_keys[k_group * i + j]);
                }
                if ((@as(u16, e) << 8) + x < q) break;
            }
        }
        return (@as(u16, e) << 8) + x;
    }
};

test "ALF-0 is a permutation of [0, q)" {
    var rk: [alf_0.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast(i * 7 + 11);

    for ([_]u16{ 100, 256 }) |q| {
        const c = try alf_0.Cipher.init(q, &rk);
        var seen: [256]bool = @splat(false);
        for (0..q) |x| {
            const y = c.encrypt(@intCast(x));
            try std.testing.expect(y < q and !seen[y]);
            seen[y] = true;
            try std.testing.expectEqual(x, c.decrypt(y));
        }
    }
}

test "ALF-1-t is a permutation of [0, q)" {
    var rk: [alf_1t.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast((i * 13 + 5) & 0xff);

    inline for (.{ .{ 4, 1000 }, .{ 3, 2048 } }) |case| {
        const t, const q = case;
        var seen: [q]bool = @splat(false);
        for (0..q) |x| {
            const y = try alf_1t.encrypt(t, q, &rk, @intCast(x));
            try std.testing.expect(y < q and !seen[y]);
            seen[y] = true;
            try std.testing.expectEqual(x, try alf_1t.decrypt(t, q, &rk, y));
        }
    }
}
