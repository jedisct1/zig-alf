//! ALF-0 and ALF-1-t: small-domain ALF variants from Appendix F.
//!
//! * ALF-0 covers Q ∈ [2, 256] by building a key-dependent secret S-box
//!   `S_Q` from r = 32 iterations of `aesenclast` over the bytes 0..255,
//!   then collapsing the 256-byte permutation to the live domain.
//! * ALF-1-t covers widths 9..15 bits (Q ∈ (2^8, 2^15]) using the Rijndael
//!   S-box with one extra bit of entropy mixed via a shifted XOR.

const std = @import("std");
const aes_core = std.crypto.core.aes;

const Block = aes_core.Block;

/// Compute the Rijndael S-box on a single byte via `aesenclast` with the
/// byte broadcast across the 16-byte block: SR + SB collapse to SB when
/// all input bytes are equal.
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

    /// Key-dependent permutation on [0, Q). `q` must lie in [2, 256].
    /// `enc_table` and `dec_table` cover only the first `q` entries; entries
    /// beyond `q` are zero-initialised but should not be accessed.
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

    /// Build the secret 256-byte permutation S256 = S ∘ ⊕RK[r-1] ∘ ... ∘ S ∘ ⊕RK[0].
    ///
    /// `aesenclast` with a single-byte round key broadcast across the block
    /// applies SR+SB+XOR; because SR commutes with byte-broadcast XOR and
    /// `SR^4 = I`, every 4 calls produce one composed Rijndael round on each
    /// position independently. With r = 32 = 8·4, the per-position effect
    /// after the full chain is S256 of the starting byte at that position.
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
        comptime if (t < 1 or t > 7) @compileError("ALF-1-t requires t ∈ [1, 7]");
    }

    fn mask(comptime t: u8) u8 {
        return (@as(u8, 1) << t) - 1;
    }

    /// Inner forward round (single round): updates (X, E) in place.
    fn forwardRound(comptime t: u8, x: *u8, e: *u8, rk: u8) void {
        const u = rijndaelSbox(x.*) ^ rk;
        x.* = u ^ (e.* << 1);
        e.* = (u ^ e.*) & mask(t);
    }

    /// Inner reverse round (single round).
    fn reverseRound(comptime t: u8, x: *u8, e: *u8, rk: u8) void {
        // Recover E from (X', E') using `clmul(X' ⊕ E', 0xff)` low t bits.
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

    /// FPE encrypt for ALF-1-t with cycle-sliding. `q` may be any value in
    /// (2^8, 2^15]; when `q == 2^(8+t)`, the cipher reduces to a plain
    /// length-preserving block cipher.
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

    /// FPE decrypt for ALF-1-t.
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

test "Rijndael Sbox via aesenclast" {
    try std.testing.expectEqual(@as(u8, 0x63), rijndaelSbox(0x00));
    try std.testing.expectEqual(@as(u8, 0x7c), rijndaelSbox(0x01));
    try std.testing.expectEqual(@as(u8, 0x16), rijndaelSbox(0xff));
    try std.testing.expectEqual(@as(u8, 0x00), rijndaelInvSbox(0x63));
    try std.testing.expectEqual(@as(u8, 0xff), rijndaelInvSbox(0x16));
}

test "ALF-0 round-trip across every plaintext" {
    const q: u16 = 100;
    var rk: [alf_0.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast(i * 7 + 11);
    const c = try alf_0.Cipher.init(q, &rk);

    var seen: [100]bool = @splat(false);
    for (0..q) |x| {
        const y = c.encrypt(@intCast(x));
        try std.testing.expect(y < q);
        try std.testing.expect(!seen[y]);
        seen[y] = true;
        try std.testing.expectEqual(@as(u8, @intCast(x)), c.decrypt(y));
    }
}

test "ALF-0 with full domain Q=256 is a permutation of [0, 256)" {
    const q: u16 = 256;
    var rk: [alf_0.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast((i * 31 + 17) & 0xff);
    const c = try alf_0.Cipher.init(q, &rk);

    var seen: [256]bool = @splat(false);
    for (0..256) |x| {
        const y = c.encrypt(@intCast(x));
        try std.testing.expect(!seen[y]);
        seen[y] = true;
    }
}

test "ALF-1-t round-trip across all plaintexts (small Q)" {
    const t: u8 = 4;
    const q: u16 = 1000;
    var rk: [alf_1t.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast((i * 13 + 5) & 0xff);

    var seen: [1000]bool = @splat(false);
    var pt: u16 = 0;
    while (pt < q) : (pt += 1) {
        const ct = try alf_1t.encrypt(t, q, &rk, pt);
        try std.testing.expect(ct < q);
        try std.testing.expect(!seen[ct]);
        seen[ct] = true;
        const back = try alf_1t.decrypt(t, q, &rk, ct);
        try std.testing.expectEqual(pt, back);
    }
}

test "ALF-1-t length-preserving (Q = 2^(8+t)) over all values" {
    const t: u8 = 3;
    const q: u16 = 1 << (8 + t); // 2048
    var rk: [alf_1t.rounds]u8 = undefined;
    for (&rk, 0..) |*b, i| b.* = @intCast((i * 53 + 99) & 0xff);

    var seen: [2048]bool = @splat(false);
    var pt: u16 = 0;
    while (pt < q) : (pt += 1) {
        const ct = try alf_1t.encrypt(t, q, &rk, pt);
        try std.testing.expect(ct < q);
        try std.testing.expect(!seen[ct]);
        seen[ct] = true;
        const back = try alf_1t.decrypt(t, q, &rk, ct);
        try std.testing.expectEqual(pt, back);
    }
}
