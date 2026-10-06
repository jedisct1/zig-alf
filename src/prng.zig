//! The two generators behind ALF-L (Appendix F.4.1 of the ALF paper).
//!
//! `BinPrng` produces random bits, 256 at a time.
//! `ModPrng` turns them into numbers below given moduli, without bias.

const std = @import("std");
const aes_core = std.crypto.core.aes;

pub const Block = aes_core.Block;

/// The keystream of the Rocca-S cipher (Algorithm 6 of the paper).
pub const BinPrng = struct {
    s: [7]Block,

    pub fn init(state: [7]Block) BinPrng {
        return .{ .s = state };
    }

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
        out[0..16].* = z0.toBytes();
        out[16..32].* = z1.toBytes();
        return out;
    }
};

/// Moduli are stored in 16 bits, with 0 standing for 2^16.
pub fn fullModulus(q: u16) u32 {
    return if (q == 0) 1 << 16 else q;
}

/// Algorithm 7 of the paper.
/// Numbers come out 16 at a time.
pub const ModPrng = struct {
    bin: BinPrng,
    pool: [8]u32 = undefined,
    pool_used: usize = 8,

    pub const block_len = 16;

    pub fn init(state: [7]Block) ModPrng {
        return .{ .bin = .init(state) };
    }

    /// One number in [0, q) for each modulus in `qs`, at most 16 of them.
    pub fn nextBlock(self: *ModPrng, qs: []const u16, samples: []u16) void {
        std.debug.assert(qs.len == samples.len and qs.len <= block_len);
        const low = self.bin.next();
        const high = self.bin.next();
        for (qs, samples, 0..) |q16, *sample, j| {
            const q: u64 = fullModulus(q16);
            const l: u64 = std.mem.readInt(u16, low[2 * j ..][0..2], .little);
            const h: u64 = std.mem.readInt(u16, high[2 * j ..][0..2], .little);
            var m = ((h << 16) | l) * q;

            // The sample is the top of the product.
            // It is slightly biased when the low 32 bits are very small, so draw again in that case.
            if (@as(u32, @truncate(m)) < q) {
                const threshold = (1 << 32) % q;
                while (@as(u32, @truncate(m)) < threshold) m = q * self.pooled();
            }
            sample.* = @intCast(m >> 32);
        }
    }

    /// Spare random words for the redraws.
    fn pooled(self: *ModPrng) u32 {
        if (self.pool_used == self.pool.len) {
            const z = self.bin.next();
            for (&self.pool, 0..) |*word, k| word.* = std.mem.readInt(u32, z[4 * k ..][0..4], .little);
            self.pool_used = 0;
        }
        defer self.pool_used += 1;
        return self.pool[self.pool_used];
    }
};

test "ModPrng stays in range and redraws biased samples" {
    var s: [7]Block = undefined;
    for (&s, 0..) |*b, i| {
        const bytes: [16]u8 = @splat(@intCast(i + 1));
        b.* = Block.fromBytes(&bytes);
    }
    var prng = ModPrng.init(s);
    var plain = BinPrng.init(s);

    // No modulus needs redraws more often than 65175, and even then only once in 2^16 samples.
    const q = 65175;
    const qs: [16]u16 = @splat(q);
    var samples: [16]u16 = undefined;
    for (0..1 << 15) |_| {
        prng.nextBlock(&qs, &samples);
        for (samples) |sample| try std.testing.expect(sample < q);
        _ = plain.next();
        _ = plain.next();
    }

    // A redraw uses extra random bits, so the two generators are no longer in step.
    try std.testing.expect(!std.mem.eql(u8, &prng.bin.next(), &plain.next()));
}
