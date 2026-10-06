//! The two generators behind ALF-L (Appendix F.4.1 of the ALF paper).
//!
//! `BinPrng` produces random bits, 256 at a time.
//! `ModPrng` turns them into numbers below given moduli, without bias.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;

/// The keystream of the Rocca-S cipher (Algorithm 6 of the paper).
pub const BinPrng = struct {
    /// The number of bytes `next` returns.
    pub const block_length = 32;

    s: [7]AesBlock,

    pub fn init(state: [7]AesBlock) BinPrng {
        return .{ .s = state };
    }

    /// Returns the next block of the keystream.
    pub fn next(prng: *BinPrng) [block_length]u8 {
        const zero: AesBlock = .fromBytes(&@splat(0));
        const s = prng.s;
        const z0 = s[3].xorBlocks(s[5]).encrypt(s[0]);
        const z1 = s[4].xorBlocks(s[6]).encrypt(s[2]);

        prng.s = .{
            s[6].xorBlocks(s[1]),
            s[0].encrypt(zero),
            s[1].encrypt(s[0]),
            s[2].encrypt(s[6]),
            s[3].encrypt(zero),
            s[4].encrypt(s[3]),
            s[5].encrypt(s[4]),
        };

        var out: [block_length]u8 = undefined;
        out[0..16].* = z0.toBytes();
        out[16..32].* = z1.toBytes();
        return out;
    }
};

/// Returns the modulus that `q` stands for.
/// Moduli are stored in 16 bits, with 0 standing for 2^16.
pub fn fullModulus(q: u16) u32 {
    return if (q == 0) 1 << 16 else q;
}

/// Algorithm 7 of the paper.
/// Numbers come out 16 at a time.
pub const ModPrng = struct {
    /// The largest number of samples `fill` can produce.
    pub const block_length = 16;

    bin: BinPrng,
    pool: [8]u32 = undefined,
    pool_used: usize = 8,

    pub fn init(state: [7]AesBlock) ModPrng {
        return .{ .bin = .init(state) };
    }

    /// Fills `samples` with one number in [0, q) for each modulus q in `moduli`.
    /// Asserts `samples.len == moduli.len` and `samples.len <= block_length`.
    pub fn fill(prng: *ModPrng, samples: []u16, moduli: []const u16) void {
        assert(samples.len == moduli.len and samples.len <= block_length);
        const low = prng.bin.next();
        const high = prng.bin.next();
        for (samples, moduli, 0..) |*sample, q16, j| {
            const q: u64 = fullModulus(q16);
            const l: u64 = mem.readInt(u16, low[2 * j ..][0..2], .little);
            const h: u64 = mem.readInt(u16, high[2 * j ..][0..2], .little);
            var m = ((h << 16) | l) * q;

            // The sample is the top of the product.
            // It is slightly biased when the low 32 bits are very small, so draw again in that case.
            if (@as(u32, @truncate(m)) < q) {
                const threshold = (1 << 32) % q;
                while (@as(u32, @truncate(m)) < threshold) m = q * prng.pooled();
            }
            sample.* = @intCast(m >> 32);
        }
    }

    // Returns a spare random word for a redraw.
    fn pooled(prng: *ModPrng) u32 {
        if (prng.pool_used == prng.pool.len) {
            const z = prng.bin.next();
            for (&prng.pool, 0..) |*word, k| word.* = mem.readInt(u32, z[4 * k ..][0..4], .little);
            prng.pool_used = 0;
        }
        defer prng.pool_used += 1;
        return prng.pool[prng.pool_used];
    }
};

const testing = std.testing;

test "ModPrng - stays in range and redraws biased samples" {
    var s: [7]AesBlock = undefined;
    for (&s, 1..) |*block, i| block.* = .fromBytes(&@splat(@intCast(i)));
    var prng: ModPrng = .init(s);
    var plain: BinPrng = .init(s);

    // No modulus needs redraws more often than 65175, and even then only once in 2^16 samples.
    const q = 65175;
    const moduli: [ModPrng.block_length]u16 = @splat(q);
    var samples: [ModPrng.block_length]u16 = undefined;
    for (0..1 << 15) |_| {
        prng.fill(&samples, &moduli);
        for (samples) |sample| try testing.expect(sample < q);
        _ = plain.next();
        _ = plain.next();
    }

    // A redraw uses extra random bits, so the two generators are no longer in step.
    try testing.expect(!mem.eql(u8, &prng.bin.next(), &plain.next()));
}
