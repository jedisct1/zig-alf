//! Demo: encrypt a 16-digit card number into another 16-digit number.

const std = @import("std");
const Io = std.Io;

const Alf = @import("alf").Alf;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const q = 10_000_000_000_000_000;
    const key: [Alf.key_length]u8 = @splat(0x42);
    const tweak: [Alf.tweak_length]u8 = @splat(0x07);
    const alf: Alf = try .init(key, tweak, 0xCAFE_F00D, q);

    const pan = 4111_1111_1111_1111;
    const encrypted_pan = try alf.encrypt(pan);
    const decrypted_pan = try alf.decrypt(encrypted_pan);

    const shape = alf.alf_nt.shape;
    try stdout.print("ALF-{d}-{d} FPE demo (q = {d})\n", .{ shape.n, shape.t, q });
    try stdout.print("  plaintext  PAN: {d:0>16}\n", .{pan});
    try stdout.print("  ciphertext PAN: {d:0>16}\n", .{encrypted_pan});
    try stdout.print("  decrypted  PAN: {d:0>16}\n", .{decrypted_pan});
    try stdout.print("  round-trip ok: {}\n", .{decrypted_pan == pan});
    try stdout.flush();
}
