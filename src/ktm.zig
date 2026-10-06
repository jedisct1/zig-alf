//! Key and tweak handling for the ALF family (Appendix F.5 of the ALF paper).
//!
//! `State.init` mixes the key, the application ID and the domain into a state.
//! The other functions turn that state and a tweak into round keys.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;

pub const key_length = 16;
pub const tweak_length = 16;

/// The "1*" block of the paper, absorbed between groups of data blocks.
pub const one_star = [_]u8{0x01} ++ @as([15]u8, @splat(0));

/// What is being encrypted.
/// A modulus of 0 stands for 2^16.
pub const Domain = union(enum) {
    /// One integer in [0, q), with q in [2, 2^144].
    integer: u160,
    /// Several symbols that all use the modulus q.
    same: struct { n: u48, q: u16 },
    /// Several symbols, each with its own modulus.
    distinct: []const u16,
};

/// The SMAC state that all the key material comes from.
pub const State = struct {
    a1: AesBlock,
    a2: AesBlock,
    a3: AesBlock,

    /// Mixes the key, the application ID and the domain into a fresh state.
    /// This is `KeyInit` in the paper.
    pub fn init(key: [key_length]u8, app_id: u64, domain: Domain) State {
        // The state starts with the symbol count N and a value Q - 1.
        // Q is the modulus for a single integer and the shared modulus for symbols that have one.
        // With distinct moduli Q is 1, and the moduli are absorbed afterwards.
        const header: struct { n: u48, q_max: u144 } = switch (domain) {
            .integer => |q| .{ .n = 1, .q_max = @intCast(q - 1) },
            .same => |s| .{ .n = s.n, .q_max = s.q -% 1 },
            .distinct => |qs| .{ .n = @intCast(qs.len), .q_max = 0 },
        };

        var a1: [16]u8 = undefined;
        mem.writeInt(u64, a1[0..8], app_id, .little);
        mem.writeInt(u48, a1[8..14], header.n, .little);
        mem.writeInt(u16, a1[14..16], @intCast(header.q_max >> 128), .little);

        var a3: [16]u8 = undefined;
        mem.writeInt(u128, &a3, @truncate(header.q_max), .little);

        const start: State = .{ .a1 = .fromBytes(&a1), .a2 = .fromBytes(&key), .a3 = .fromBytes(&a3) };
        var state = start.initFinal(1);
        if (domain == .distinct) state.compressBiased(domain.distinct, 1);
        return state;
    }

    /// Absorbs one block.
    /// This is the round function of SMAC.
    pub fn update(state: *State, m: AesBlock) void {
        const s = state.*;
        state.* = .{
            .a1 = shuffleSigma42(s.a2.xorBlocks(s.a3).xorBlocks(m)),
            .a2 = s.a1.encrypt(m),
            .a3 = s.a2.encrypt(m),
        };
    }

    /// Returns a scrambled copy of the state.
    /// Different values of `c` give unrelated results.
    pub fn initFinal(state: State, c: u32) State {
        var bytes: [16]u8 = @splat(0);
        mem.writeInt(u32, bytes[0..4], c, .little);
        const m: AesBlock = .fromBytes(&bytes);

        var s = state;
        for (0..9) |_| s.update(m);
        return .{
            .a1 = state.a1.xorBlocks(s.a1),
            .a2 = state.a2.xorBlocks(s.a2),
            .a3 = state.a3.xorBlocks(s.a3),
        };
    }

    /// Absorbs a list of 16-bit values.
    /// This is `SCompress` in the paper.
    pub fn compress(state: *State, values: []const u16) void {
        state.compressBiased(values, 0);
    }

    // Absorbs `values[i] - bias`.
    // The key setup needs each modulus minus one, and this avoids copying the list.
    fn compressBiased(state: *State, values: []const u16, bias: u16) void {
        const one_star_block: AesBlock = .fromBytes(&one_star);

        var blocks: usize = 0;
        var i: usize = 0;
        while (i < values.len) : (i += 8) {
            var bytes: [16]u8 = @splat(0);
            const chunk = values[i..@min(i + 8, values.len)];
            for (chunk, 0..) |value, j| mem.writeInt(u16, bytes[2 * j ..][0..2], value -% bias, .little);
            state.update(.fromBytes(&bytes));
            blocks += 1;
            if (blocks % 3 == 0) state.update(one_star_block);
        }
        if (blocks % 3 != 0) state.update(one_star_block);
    }

    /// Returns a copy of the state with the tweak absorbed.
    /// This is `TweakCompress` in the paper.
    pub fn withTweak(state: State, tweak: [tweak_length]u8) State {
        var tweaked = state;
        tweaked.update(.fromBytes(&tweak));
        return tweaked;
    }

    /// Fills `out` with key material.
    /// `d` keeps the different uses of one state apart.
    pub fn deriveBytes(state: State, out: []u8, d: u8) void {
        var offset: usize = 0;
        var c: u32 = 1;
        while (offset < out.len) : (c += 1) {
            const chunk = state.initFinal((@as(u32, d) << 8) | c).toBytes();
            const len = @min(out.len - offset, chunk.len);
            @memcpy(out[offset..][0..len], chunk[0..len]);
            offset += len;
        }
    }

    /// Fills `round_keys` with round keys of `n` bytes each.
    /// Bytes past `n` are zero.
    pub fn deriveRoundKeys(state: State, round_keys: []AesBlock, n: usize, d: u8) void {
        var buf: [16 * 32]u8 = undefined;
        assert(n <= 16 and round_keys.len <= 32);
        state.deriveBytes(buf[0 .. n * round_keys.len], d);

        for (round_keys, 0..) |*round_key, i| {
            var bytes: [16]u8 = @splat(0);
            @memcpy(bytes[0..n], buf[i * n ..][0..n]);
            round_key.* = .fromBytes(&bytes);
        }
    }

    pub fn toBytes(state: State) [48]u8 {
        var bytes: [48]u8 = undefined;
        bytes[0..16].* = state.a1.toBytes();
        bytes[16..32].* = state.a2.toBytes();
        bytes[32..48].* = state.a3.toBytes();
        return bytes;
    }
};

const sigma42: @Vector(16, i32) = .{ 7, 14, 15, 10, 12, 13, 3, 0, 4, 6, 1, 5, 8, 11, 2, 9 };

fn shuffleSigma42(x: AesBlock) AesBlock {
    const src: @Vector(16, u8) = x.toBytes();
    const out: [16]u8 = @shuffle(u8, src, undefined, sigma42);
    return .fromBytes(&out);
}
