//! Demo: encrypt a 16-digit card number into another 16-digit number.

const std = @import("std");
const Io = std.Io;

const alf = @import("alf");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_file_writer.interface;

    const q = 10_000_000_000_000_000;
    const key: [16]u8 = @splat(0x42);
    const tweak: [16]u8 = @splat(0x07);
    const cipher: alf.alf_int.Cipher = try .init(key, tweak, 0xCAFE_F00D, q);

    const pan = 4111_1111_1111_1111;
    const cipher_pan = try cipher.encrypt(pan);
    const back = try cipher.decrypt(cipher_pan);

    try out.print("ALF-{d}-{d} FPE demo (Q = {d})\n", .{ cipher.alfnt.n, cipher.alfnt.t, q });
    try out.print("  plaintext  PAN: {d:0>16}\n", .{pan});
    try out.print("  ciphertext PAN: {d:0>16}\n", .{cipher_pan});
    try out.print("  decrypted  PAN: {d:0>16}\n", .{back});
    try out.print("  round-trip ok: {}\n", .{back == pan});
    try out.flush();
}
