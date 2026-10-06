//! Key and tweak handling for the ALF family (Appendix F.5 of the ALF paper).
//!
//! `keyInit` mixes the key, the application ID and the domain into a state.
//! The other functions turn that state and a tweak into round keys.

const std = @import("std");
const aes_core = std.crypto.core.aes;

pub const Block = aes_core.Block;

/// The "1*" block of the paper, absorbed between groups of data blocks.
pub const one_star: [16]u8 = blk: {
    var b: [16]u8 = @splat(0);
    b[0] = 0x01;
    break :blk b;
};

pub const State = struct {
    a1: Block,
    a2: Block,
    a3: Block,

    pub fn xor(self: State, other: State) State {
        return .{
            .a1 = self.a1.xorBlocks(other.a1),
            .a2 = self.a2.xorBlocks(other.a2),
            .a3 = self.a3.xorBlocks(other.a3),
        };
    }

    pub fn toBytes(self: State) [48]u8 {
        var out: [48]u8 = undefined;
        out[0..16].* = self.a1.toBytes();
        out[16..32].* = self.a2.toBytes();
        out[32..48].* = self.a3.toBytes();
        return out;
    }
};

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

const sigma42: @Vector(16, i32) = .{ 7, 14, 15, 10, 12, 13, 3, 0, 4, 6, 1, 5, 8, 11, 2, 9 };

fn shuffleSigma42(x: Block) Block {
    const src: @Vector(16, u8) = x.toBytes();
    const out: [16]u8 = @shuffle(u8, src, undefined, sigma42);
    return Block.fromBytes(&out);
}

/// Absorb one block into the state.
pub fn smacR(state: State, m: Block) State {
    return .{
        .a1 = shuffleSigma42(state.a2.xorBlocks(state.a3).xorBlocks(m)),
        .a2 = state.a1.encrypt(m),
        .a3 = state.a2.encrypt(m),
    };
}

/// Scramble the state.
/// Different values of `c` give unrelated results.
pub fn initFinal(state: State, c: u32) State {
    var bytes: [16]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], c, .little);
    const m = Block.fromBytes(&bytes);
    var s = state;
    for (0..9) |_| s = smacR(s, m);
    return state.xor(s);
}

/// Absorb a list of 16-bit values.
pub fn sCompress(state: State, values: []const u16) State {
    return sCompressBiased(state, values, 0);
}

/// Absorb `values[i] - bias`.
/// The key setup needs each modulus minus one, and this avoids copying the list.
fn sCompressBiased(state: State, values: []const u16, bias: u16) State {
    var s = state;
    const one_star_blk = Block.fromBytes(&one_star);

    var blocks: usize = 0;
    var i: usize = 0;
    while (i < values.len) : (i += 8) {
        var bytes: [16]u8 = @splat(0);
        var j: usize = 0;
        while (j < 8 and i + j < values.len) : (j += 1) {
            std.mem.writeInt(u16, bytes[2 * j ..][0..2], values[i + j] -% bias, .little);
        }
        s = smacR(s, Block.fromBytes(&bytes));
        blocks += 1;
        if (blocks % 3 == 0) s = smacR(s, one_star_blk);
    }
    if (blocks % 3 != 0) s = smacR(s, one_star_blk);
    return s;
}

/// Mix the key, the application ID and the domain into a fresh state.
pub fn keyInit(key: [16]u8, app_id: u64, domain: Domain) State {
    // The state starts with the symbol count N and a value Q - 1.
    // Q is the modulus for a single integer and the shared modulus for symbols that have one.
    // With distinct moduli Q is 1, and the moduli are absorbed afterwards.
    const header: struct { n: u48, q_max: u144 } = switch (domain) {
        .integer => |q| .{ .n = 1, .q_max = @intCast(q - 1) },
        .same => |s| .{ .n = s.n, .q_max = s.q -% 1 },
        .distinct => |qs| .{ .n = @intCast(qs.len), .q_max = 0 },
    };

    var a1_bytes: [16]u8 = undefined;
    std.mem.writeInt(u64, a1_bytes[0..8], app_id, .little);
    std.mem.writeInt(u48, a1_bytes[8..14], header.n, .little);
    std.mem.writeInt(u16, a1_bytes[14..16], @intCast(header.q_max >> 128), .little);

    var a3_bytes: [16]u8 = undefined;
    std.mem.writeInt(u128, &a3_bytes, @truncate(header.q_max), .little);

    var state: State = .{
        .a1 = Block.fromBytes(&a1_bytes),
        .a2 = Block.fromBytes(&key),
        .a3 = Block.fromBytes(&a3_bytes),
    };
    state = initFinal(state, 1);
    if (domain == .distinct) state = sCompressBiased(state, domain.distinct, 1);
    return state;
}

/// Absorb the tweak.
pub fn tweakCompress(state: State, tweak: [16]u8) State {
    return smacR(state, Block.fromBytes(&tweak));
}

/// Fill `out` with key material.
/// `d` keeps the different uses of one state apart.
pub fn deriveBytes(state: State, d: u8, out: []u8) void {
    var offset: usize = 0;
    var c: u32 = 1;
    while (offset < out.len) : (c += 1) {
        const chunk = initFinal(state, (@as(u32, d) << 8) | c).toBytes();
        const take = @min(out.len - offset, chunk.len);
        @memcpy(out[offset..][0..take], chunk[0..take]);
        offset += take;
    }
}

/// Derive `rounds` round keys of n bytes each.
/// Bytes past n are zero.
pub fn deriveRoundKeys(
    n: u8,
    rounds: u8,
    post_tweak_state: State,
    d: u8,
    out: []Block,
) void {
    std.debug.assert(out.len == rounds);
    const total_bytes = @as(usize, n) * rounds;
    var buf: [16 * 32]u8 = undefined;
    std.debug.assert(total_bytes <= buf.len);
    deriveBytes(post_tweak_state, d, buf[0..total_bytes]);

    for (out, 0..) |*rk, i| {
        var bytes: [16]u8 = @splat(0);
        @memcpy(bytes[0..n], buf[i * n ..][0..n]);
        rk.* = Block.fromBytes(&bytes);
    }
}

pub fn alfNtRoundKeys(n: u8, rounds: u8, state: State, tweak: [16]u8, out: []Block) void {
    deriveRoundKeys(n, rounds, tweakCompress(state, tweak), 0, out);
}

pub fn alf16tRoundKeys(state: State, tweak: [16]u8, out: *[12]Block) void {
    deriveRoundKeys(16, 12, tweakCompress(state, tweak), 0, out);
}

pub fn alf0RoundKeys(state: State, tweak: [16]u8, out: *[32]u8) void {
    deriveBytes(tweakCompress(state, tweak), 0, out);
}

pub fn alf1tRoundKeys(state: State, tweak: [16]u8, out: *[48]u8) void {
    deriveBytes(tweakCompress(state, tweak), 0, out);
}
