//! Checks against the test vectors of the ALF reference implementation.
//! See `testdata/README.md` for where they come from.
//!
//! Each vector starts from zero and gives the result after 1, 5 and 999 encryptions.

const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const testing = std.testing;

const ktm = @import("ktm.zig");
const Alf = @import("alf_int.zig").Alf;
const AlfL = @import("alf_l.zig").AlfL;

const vectors = @embedFile("testdata/testvec.hpp");

const ref_app_id: u64 = 0xf1f2f3f4f5f6f7f8;
const ref_key = [Alf.key_length]u8{ 0x05, 0x0a, 0x0f, 0x14, 0x19, 0x1e, 0x23, 0x28, 0x2d, 0x32, 0x37, 0x3c, 0x41, 0x46, 0x4b, 0x50 };
const ref_tweak = [Alf.tweak_length]u8{ 0x0b, 0x16, 0x21, 0x2c, 0x37, 0x42, 0x4d, 0x58, 0x63, 0x6e, 0x79, 0x84, 0x8f, 0x9a, 0xa5, 0xb0 };

// Moduli of the D vectors, each minus one.
// A vector of length N uses the last N entries.
const ref_q_max = [128]u16{
    0x0008, 0x0004, 0x0001, 0x0000, 0x0003, 0x000e, 0x0029, 0x0064, 0x00df, 0x01da, 0x03d5, 0x07d0, 0x0fcb, 0x1fc6, 0x3fc1, 0x7fbc,
    0x0005, 0x0000, 0xfffc, 0xfffa, 0xfffc, 0x0006, 0x0020, 0x005a, 0x00d4, 0x01ce, 0x03c8, 0x07c2, 0x0fbc, 0x1fb6, 0x3fb0, 0x7faa,
    0x0002, 0xfffc, 0xfff7, 0xfff4, 0xfff5, 0xfffe, 0x0017, 0x0050, 0x00c9, 0x01c2, 0x03bb, 0x07b4, 0x0fad, 0x1fa6, 0x3f9f, 0x7f98,
    0xffff, 0xfff8, 0xfff2, 0xffee, 0xffee, 0xfff6, 0x000e, 0x0046, 0x00be, 0x01b6, 0x03ae, 0x07a6, 0x0f9e, 0x1f96, 0x3f8e, 0x7f86,
    0xfffc, 0xfff4, 0xffed, 0xffe8, 0xffe7, 0xffee, 0x0005, 0x003c, 0x00b3, 0x01aa, 0x03a1, 0x0798, 0x0f8f, 0x1f86, 0x3f7d, 0x7f74,
    0xfff9, 0xfff0, 0xffe8, 0xffe2, 0xffe0, 0xffe6, 0xfffc, 0x0032, 0x00a8, 0x019e, 0x0394, 0x078a, 0x0f80, 0x1f76, 0x3f6c, 0x7f62,
    0xfff6, 0xffec, 0xffe3, 0xffdc, 0xffd9, 0xffde, 0xfff3, 0x0028, 0x009d, 0x0192, 0x0387, 0x077c, 0x0f71, 0x1f66, 0x3f5b, 0x7f50,
    0xfff3, 0xffe8, 0xffde, 0xffd6, 0xffd2, 0xffd6, 0xffea, 0x001e, 0x0092, 0x0186, 0x037a, 0x076e, 0x0f62, 0x1f56, 0x3f4a, 0x7f3e,
};

const ref_moduli = blk: {
    var qs: [ref_q_max.len]u16 = undefined;
    for (&qs, ref_q_max) |*q, q_max| q.* = q_max +% 1;
    break :blk qs;
};

const iterations = 999;

const Kind = enum(u8) {
    /// T: one integer.
    integer,
    /// S: symbols with the same modulus.
    same,
    /// D: symbols with distinct moduli.
    distinct,
    /// C: the use cases listed in the paper.
    use_case,

    fn letter(kind: Kind) u8 {
        return "TSDC"[@backingInt(kind)];
    }
};

const Vector = struct {
    kind: Kind,
    idx: u32,
    n: usize,
    q_same_max: u16,
    q_offset: u16,
    q_max: u192,
    key_state: [48]u8,
    enc_material: [64]u8,
    dec_material: [64]u8,
    enc: [3][32]u8,

    const field_count = 5 + 3 + 48 + 64 + 64 + 3 * 32;
    const no_offset = 0xffff;

    fn parse(line: []const u8) !Vector {
        const body = line[mem.indexOf(u8, line, "*/").? + 2 ..];
        var tokens = mem.tokenizeAny(u8, body, " {},\r\t");
        var fields: [field_count]u64 = undefined;
        var count: usize = 0;
        while (tokens.next()) |raw| : (count += 1) {
            if (count == fields.len) return error.MalformedVector;
            fields[count] = try fmt.parseInt(u64, mem.trimEnd(u8, raw, "UL"), 0);
        }
        if (count != fields.len) return error.MalformedVector;

        var v: Vector = undefined;
        v.kind = std.enums.fromInt(Kind, fields[0]) orelse return error.MalformedVector;
        v.idx = @intCast(fields[1]);
        v.n = @intCast(fields[2]);
        v.q_same_max = @intCast(fields[3]);
        v.q_offset = @intCast(fields[4]);
        v.q_max = @as(u192, fields[5]) | (@as(u192, fields[6]) << 64) | (@as(u192, fields[7]) << 128);

        var rest: []const u64 = fields[8..];
        inline for (.{ &v.key_state, &v.enc_material, &v.dec_material, &v.enc[0], &v.enc[1], &v.enc[2] }) |dest| {
            for (dest, rest[0..dest.len]) |*byte, field| byte.* = @intCast(field);
            rest = rest[dest.len..];
        }
        return v;
    }

    fn moduli(vector: Vector) AlfL.Moduli {
        if (vector.q_offset == no_offset) return .{ .same = vector.q_same_max +% 1 };
        return .{ .distinct = ref_moduli[vector.q_offset..][0..vector.n] };
    }

    fn expectEqual(vector: Vector, what: []const u8, expected: []const u8, actual: []const u8) !void {
        if (mem.eql(u8, expected, actual)) return;
        std.debug.print("vector {c}{d}: wrong {s}\n", .{ vector.kind.letter(), vector.idx, what });
        return testing.expectEqualSlices(u8, expected, actual);
    }

    // Checks the result of the given iteration, if the vector records it.
    fn expectSnapshot(vector: Vector, iteration: usize, actual: [32]u8) !void {
        const index: usize = switch (iteration) {
            1 => 0,
            5 => 1,
            iterations => 2,
            else => return,
        };
        var name: [16]u8 = undefined;
        const what = fmt.bufPrint(&name, "Enc^{d}(0)", .{iteration}) catch unreachable;
        try vector.expectEqual(what, &vector.enc[index], &actual);
    }
};

const VectorIterator = struct {
    lines: mem.SplitIterator(u8, .scalar) = mem.splitScalar(u8, vectors, '\n'),

    fn next(it: *VectorIterator) !?Vector {
        while (it.lines.next()) |line| {
            if (mem.startsWith(u8, line, "/*[")) return try Vector.parse(line);
        }
        return null;
    }
};

// Returns the key material a vector records:
// the start of the S-box for ALF-0, the first round keys for the others.
fn material(alf: *const Alf, comptime side: enum { enc, dec }) [64]u8 {
    var out: [64]u8 = @splat(0);
    switch (alf.*) {
        .alf_0 => |*variant| {
            const len = @min(variant.q, 16);
            const table = if (side == .enc) &variant.enc_table else &variant.dec_table;
            @memcpy(out[0..len], table[0..len]);
        },
        .alf_1t => |*variant| out[0..16].* = variant.round_keys[0..16].*,
        .alf_nt => |*variant| {
            const n = variant.shape.n;
            const keys = if (side == .enc) &variant.enc_keys else &variant.dec_keys;
            for (0..4) |r| @memcpy(out[16 * r ..][0..n], keys[r].toBytes()[0..n]);
        },
        .alf_16t => |*variant| {
            const keys = if (side == .enc) &variant.enc_keys else &variant.dec_keys;
            for (0..4) |r| out[16 * r ..][0..16].* = keys[r].toBytes();
        },
    }
    return out;
}

fn integerSnapshot(x: u160) [32]u8 {
    var out: [32]u8 = @splat(0);
    mem.writeInt(u192, out[0..24], x, .little);
    return out;
}

// Vectors only record the first 16 symbols.
fn symbolSnapshot(symbols: []const u16) [32]u8 {
    var out: [32]u8 = @splat(0);
    for (symbols[0..@min(symbols.len, 16)], 0..) |symbol, i| mem.writeInt(u16, out[2 * i ..][0..2], symbol, .little);
    return out;
}

test "Alf - single integers (T vectors)" {
    var it: VectorIterator = .{};
    var count: usize = 0;
    while (try it.next()) |v| {
        if (v.kind != .integer) continue;
        count += 1;

        const q: u160 = @intCast(v.q_max + 1);
        const state: ktm.State = .init(ref_key, ref_app_id, .{ .integer = q });
        try v.expectEqual("KeyInit state", &v.key_state, &state.toBytes());

        const alf: Alf = try .init(ref_key, ref_tweak, ref_app_id, q);
        try v.expectEqual("encryption keys", &v.enc_material, &material(&alf, .enc));
        try v.expectEqual("decryption keys", &v.dec_material, &material(&alf, .dec));

        var x: u160 = 0;
        for (1..iterations + 1) |i| {
            x = try alf.encrypt(x);
            try v.expectSnapshot(i, integerSnapshot(x));
        }
        for (0..iterations) |_| x = try alf.decrypt(x);
        try testing.expectEqual(0, x);
    }
    try testing.expectEqual(68, count);
}

fn expectVectorKind(kind: Kind, expected_count: usize) !void {
    const allocator = testing.allocator;
    var it: VectorIterator = .{};
    var count: usize = 0;
    while (try it.next()) |v| {
        if (v.kind != kind) continue;
        count += 1;

        const moduli = v.moduli();
        const symbols = try allocator.alloc(u16, v.n);
        defer allocator.free(symbols);
        @memset(symbols, 0);

        for (1..iterations + 1) |i| {
            try AlfL.encrypt(symbols, symbols, moduli, ref_app_id, ref_tweak, ref_key);
            try v.expectSnapshot(i, symbolSnapshot(symbols));
        }
        for (0..iterations) |_| try AlfL.decrypt(symbols, symbols, moduli, ref_app_id, ref_tweak, ref_key);
        if (!mem.allEqual(u16, symbols, 0)) {
            std.debug.print("vector {c}{d}: decryption does not lead back to zero\n", .{ v.kind.letter(), v.idx });
            return error.TestExpectedEqual;
        }
    }
    try testing.expectEqual(expected_count, count);
}

test "AlfL - symbols with the same modulus (S vectors)" {
    try expectVectorKind(.same, 31);
}

test "AlfL - symbols with distinct moduli (D vectors)" {
    try expectVectorKind(.distinct, 127);
}

test "AlfL - use cases of the paper (C vectors)" {
    try expectVectorKind(.use_case, 7);
}

test "AlfL - a vector of one symbol is encrypted like a single integer" {
    var it: VectorIterator = .{};
    var count: usize = 0;
    while (try it.next()) |v| {
        if (v.kind != .integer or v.q_max > 0xffff) continue;
        count += 1;

        const q: u16 = @truncate(v.q_max + 1);
        for ([_]AlfL.Moduli{ .{ .same = q }, .{ .distinct = &.{q} } }) |moduli| {
            var symbol = [1]u16{0};
            for (1..iterations + 1) |i| {
                try AlfL.encrypt(&symbol, &symbol, moduli, ref_app_id, ref_tweak, ref_key);
                try v.expectSnapshot(i, symbolSnapshot(&symbol));
            }
        }
    }
    try testing.expectEqual(6, count);
}
