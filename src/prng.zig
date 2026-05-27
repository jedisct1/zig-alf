//! BinPRNG and ModPRNG used by ALF-L.
//!
//! `BinPRNG` is the Rocca-S keystream (Algorithm 6 of the ALF paper): a
//! seven-register, AES-NI-based state that emits 256 bits per call. `ModPRNG`
//! (Algorithm 7) layers an unbiased rejection sampler on top of `BinPRNG` to
//! produce a stream of integers each modulo a per-position bound q_i ≤ 2^16.
//!
//! For ALF-L use, the initial state of `BinPRNG` is supplied by the KTM (see
//! `ktm.zig`).

const std = @import("std");
const aes_core = std.crypto.core.aes;

pub const Block = aes_core.Block;

pub const BinPrng = struct {
    s: [7]Block,

    pub fn init(state: [7]Block) BinPrng {
        return .{ .s = state };
    }

    /// Emit 32 bytes (Z0 || Z1) and advance the state per Algorithm 6.
    pub fn next(self: *BinPrng) [32]u8 {
        const zero_bytes: [16]u8 = @splat(0);
        const zero = Block.fromBytes(&zero_bytes);
        const s = self.s;
        const z0 = s[3].xorBlocks(s[5]).encrypt(s[0]);
        const z1 = s[4].xorBlocks(s[6]).encrypt(s[2]);

        var ns: [7]Block = undefined;
        ns[0] = s[6].xorBlocks(s[1]);
        ns[1] = s[0].encrypt(zero);
        ns[2] = s[1].encrypt(s[0]);
        ns[3] = s[2].encrypt(s[6]);
        ns[4] = s[3].encrypt(zero);
        ns[5] = s[4].encrypt(s[3]);
        ns[6] = s[5].encrypt(s[4]);
        self.s = ns;

        var out: [32]u8 = undefined;
        @memcpy(out[0..16], &z0.toBytes());
        @memcpy(out[16..32], &z1.toBytes());
        return out;
    }
};

/// Generate one 16-bit sample uniformly in [0, q) using the BinPRNG.
/// Lemire-style: draw a 16-bit value, multiply by q to land in a 32-bit
/// product, retain the high 16 bits as a candidate, retry when the low 16
/// bits fall below `(2^16 mod q)` to avoid bias.
pub fn modSample16(prng: *BinPrng, pool: *Pool32, q: u32) u16 {
    if (q == 0 or q >= (1 << 16)) {
        // q = 0 in the paper means modulus 2^16, return raw bits.
        const r = pool.next16(prng);
        return r;
    }
    const bias = ((@as(u32, 1) << 16) % q);
    while (true) {
        const r: u32 = pool.next16(prng);
        const m = r * q;
        const low: u32 = m & 0xffff;
        if (low >= bias) return @intCast(m >> 16);
    }
}

/// Small reservoir of 16-bit halves consumed by `modSample16`. Each call to
/// `next16` pulls a 16-bit chunk from the cached 256-bit BinPRNG output,
/// refilling on demand. This is the scalar fall-back path of ModPRNG's loop.
pub const Pool32 = struct {
    buf: [32]u8 = undefined,
    pos: u8 = 32,

    pub fn next16(self: *Pool32, prng: *BinPrng) u16 {
        if (self.pos + 2 > 32) {
            self.buf = prng.next();
            self.pos = 0;
        }
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .little);
        self.pos += 2;
        return v;
    }
};

/// ModPRNG: generate N samples si ∈ [0, q_i). qs.len must equal samples.len.
/// `qs[i] = 0` is interpreted as modulus 2^16 (per the spec's API convention).
pub fn modPrng(prng: *BinPrng, qs: []const u16, samples: []u16) void {
    std.debug.assert(qs.len == samples.len);
    var pool: Pool32 = .{};
    for (qs, samples) |q, *s| s.* = modSample16(prng, &pool, q);
}

test "BinPRNG deterministic from a fixed state" {
    var s: [7]Block = undefined;
    for (&s, 0..) |*b, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*x, j| x.* = @intCast((i * 16 + j) & 0xff);
        b.* = Block.fromBytes(&bytes);
    }
    var p1 = BinPrng.init(s);
    var p2 = BinPrng.init(s);
    try std.testing.expectEqualSlices(u8, &p1.next(), &p2.next());
    try std.testing.expectEqualSlices(u8, &p1.next(), &p2.next());
}

test "ModPRNG produces samples within bounds" {
    var s: [7]Block = undefined;
    for (&s, 0..) |*b, i| {
        var bytes: [16]u8 = undefined;
        for (&bytes, 0..) |*x, j| x.* = @intCast((i * 16 + j + 1) & 0xff);
        b.* = Block.fromBytes(&bytes);
    }
    var prng = BinPrng.init(s);
    const qs = [_]u16{ 10, 100, 1000, 60000, 256, 7, 13, 1 };
    var samples: [qs.len]u16 = undefined;
    modPrng(&prng, &qs, &samples);
    for (qs, samples) |q, sample| try std.testing.expect(sample < q);
}
