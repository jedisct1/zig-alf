//! Cross-variant integration tests.

const std = @import("std");
const alf = @import("root.zig");

test "every (n, t) round trips via KTM" {
    @setEvalBranchQuota(40_000);
    const ns = [_]u8{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const ts = [_]u8{ 0, 1, 4, 7 };

    const key: [16]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const tweak: [16]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };

    inline for (ns) |n| {
        inline for (ts) |t| {
            const rounds = alf.alf_nt.roundCount(n, t);
            const q: u128 = 1 << (8 * n + t);
            var enc_rk: [alf.alf_nt.max_rounds]alf.Block = undefined;
            alf.ktm.alfNtRoundKeys(n, rounds, key, tweak, 0, q, enc_rk[0..rounds]);
            var dec_rk: [alf.alf_nt.max_rounds]alf.Block = undefined;
            alf.alf_nt.prepareDecryption(n, enc_rk[0..rounds], dec_rk[0..rounds]);

            const trail: usize = comptime @intFromBool(t != 0);
            var pt: [16]u8 = undefined;
            for (&pt, 0..) |*b, i| b.* = @intCast((i * 17 + 3) & 0xff);
            if (t != 0) {
                const m: u8 = (@as(u8, 1) << t) - 1;
                pt[n] &= m;
            }
            var ct: [16]u8 = undefined;
            var back: [16]u8 = undefined;
            try alf.alf_nt.encrypt(n, t, enc_rk[0..rounds], &pt, &ct);
            try alf.alf_nt.decrypt(n, t, dec_rk[0..rounds], &ct, &back);
            try std.testing.expectEqualSlices(u8, pt[0 .. n + trail], back[0 .. n + trail]);
        }
    }
}

test "FPE: round-trip across several moduli with KTM keys" {
    @setEvalBranchQuota(40_000);
    const cases = .{
        .{ .n = 3, .t = 0, .q = @as(u128, 50000) }, // 24-bit cipher, sub-domain
        .{ .n = 6, .t = 6, .q = @as(u128, 10_000_000_000_000_000) }, // 16 decimal digits
        .{ .n = 12, .t = 0, .q = @as(u128, 1) << 96 }, // IPv6
    };
    const key: [16]u8 = @splat(0x5a);
    const tweak: [16]u8 = @splat(0xa5);

    inline for (cases) |c| {
        const r = alf.alf_nt.roundCount(c.n, c.t);
        var enc_rk: [alf.alf_nt.max_rounds]alf.Block = undefined;
        alf.ktm.alfNtRoundKeys(c.n, r, key, tweak, 1, c.q, enc_rk[0..r]);
        var dec_rk: [alf.alf_nt.max_rounds]alf.Block = undefined;
        alf.alf_nt.prepareDecryption(c.n, enc_rk[0..r], dec_rk[0..r]);

        var rng = std.Random.DefaultPrng.init(0x1234);
        const rand = rng.random();
        for (0..16) |_| {
            const pt = rand.uintLessThan(u128, c.q);
            const ct = try alf.fpe.encryptInt(c.n, c.t, c.q, enc_rk[0..r], pt);
            try std.testing.expect(ct < c.q);
            const back = try alf.fpe.decryptInt(c.n, c.t, c.q, dec_rk[0..r], ct);
            try std.testing.expectEqual(pt, back);
        }
    }
}

test "ALF-0 + ALF-1-t + ALF-16-t with KTM keys" {
    const key: [16]u8 = @splat(0x33);
    const tweak: [16]u8 = @splat(0xcc);

    // ALF-0
    var rk0: [32]u8 = undefined;
    alf.ktm.alf0RoundKeys(key, tweak, 99, 200, &rk0);
    const c0 = try alf.alf_small.alf_0.Cipher.init(200, &rk0);
    for (0..200) |x| {
        const y = c0.encrypt(@intCast(x));
        try std.testing.expectEqual(@as(u8, @intCast(x)), c0.decrypt(y));
    }

    // ALF-1-t
    var rk1: [48]u8 = undefined;
    alf.ktm.alf1tRoundKeys(key, tweak, 99, 30000, &rk1);
    var pt: u16 = 0;
    while (pt < 100) : (pt += 1) {
        const ct = try alf.alf_small.alf_1t.encrypt(7, 30000, &rk1, pt);
        const back = try alf.alf_small.alf_1t.decrypt(7, 30000, &rk1, ct);
        try std.testing.expectEqual(pt, back);
    }

    // ALF-16-t
    const q16: u160 = (@as(u160, 1) << 143) - 1;
    var rk16: [12]alf.Block = undefined;
    alf.ktm.alf16tRoundKeys(key, tweak, 99, q16, &rk16);
    var dec16: [12]alf.Block = undefined;
    alf.alf_16t.prepareDecryption(&rk16, &dec16);
    var rng = std.Random.DefaultPrng.init(11);
    const rand = rng.random();
    for (0..8) |_| {
        var pt16: u160 = (@as(u160, rand.int(u128))) | (@as(u160, rand.int(u16)) << 128);
        pt16 %= q16;
        const ct = try alf.alf_16t.encryptInt(15, q16, &rk16, pt16);
        try std.testing.expect(ct < q16);
        const back = try alf.alf_16t.decryptInt(15, q16, &dec16, ct);
        try std.testing.expectEqual(pt16, back);
    }
}
