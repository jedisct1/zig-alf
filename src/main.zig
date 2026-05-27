//! Tiny demo: encrypt a 16-digit credit-card number with cycle-sliding ALF-n-t.

const std = @import("std");
const Io = std.Io;

const zig_alf = @import("zig_alf");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_file_writer.interface;

    // 16 decimal digits of credit-card → modulus 10^16, which fits in a
    // 54-bit cipher (ALF-6-6).
    const n: u8 = 6;
    const t: u8 = 6;
    const q: u128 = 10_000_000_000_000_000;
    const rounds = zig_alf.alf_nt.roundCount(n, t);

    const key: [16]u8 = @splat(0x42);
    const tweak: [16]u8 = @splat(0x07);

    var enc_rk: [zig_alf.alf_nt.max_rounds]zig_alf.Block = undefined;
    zig_alf.ktm.alfNtRoundKeys(n, rounds, key, tweak, 0xCAFE_F00D, q, enc_rk[0..rounds]);
    var dec_rk: [zig_alf.alf_nt.max_rounds]zig_alf.Block = undefined;
    zig_alf.alf_nt.prepareDecryption(n, enc_rk[0..rounds], dec_rk[0..rounds]);

    const pan: u128 = 4111_1111_1111_1111;
    const cipher_pan = try zig_alf.fpe.encryptInt(n, t, q, enc_rk[0..rounds], pan);
    const back = try zig_alf.fpe.decryptInt(n, t, q, dec_rk[0..rounds], cipher_pan);

    try out.print("ALF-{d}-{d} FPE demo (Q = {d})\n", .{ n, t, q });
    try out.print("  plaintext  PAN: {d:0>16}\n", .{pan});
    try out.print("  ciphertext PAN: {d:0>16}\n", .{cipher_pan});
    try out.print("  decrypted  PAN: {d:0>16}\n", .{back});
    try out.print("  round-trip ok: {}\n", .{back == pan});
    try out.flush();
}

test "demo encrypt/decrypt is consistent" {
    const n: u8 = 6;
    const t: u8 = 6;
    const q: u128 = 10_000_000_000_000_000;
    const rounds = zig_alf.alf_nt.roundCount(n, t);

    const key: [16]u8 = @splat(0x42);
    const tweak: [16]u8 = @splat(0x07);

    var enc_rk: [zig_alf.alf_nt.max_rounds]zig_alf.Block = undefined;
    zig_alf.ktm.alfNtRoundKeys(n, rounds, key, tweak, 0xCAFE_F00D, q, enc_rk[0..rounds]);
    var dec_rk: [zig_alf.alf_nt.max_rounds]zig_alf.Block = undefined;
    zig_alf.alf_nt.prepareDecryption(n, enc_rk[0..rounds], dec_rk[0..rounds]);

    const pan: u128 = 4111_1111_1111_1111;
    const cipher_pan = try zig_alf.fpe.encryptInt(n, t, q, enc_rk[0..rounds], pan);
    try std.testing.expect(cipher_pan < q);
    const back = try zig_alf.fpe.decryptInt(n, t, q, dec_rk[0..rounds], cipher_pan);
    try std.testing.expectEqual(pan, back);
}
