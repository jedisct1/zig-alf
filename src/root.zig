//! The ALF family of format-preserving ciphers, built on AES rounds.
//!
//! Start here:
//!
//! * `alf_int` encrypts one integer in [0, Q), for any Q up to 2^144.
//! * `alf_l` encrypts a vector of 16-bit symbols, each with its own modulus.
//!
//! Both pick the right cipher for the size of the domain.
//! The pieces they are made of:
//!
//! * `alf_small`: ALF-0 and ALF-1-t, for Q up to 2^15.
//! * `alf_nt` and `fpe`: ALF-n-t, for 16 to 127 bits.
//! * `alf_16t`: ALF-16-t, for 128 to 144 bits.
//! * `ktm`: turns the key and the tweak into round keys.
//! * `prng`: the keystream used for long vectors.

const std = @import("std");

pub const tables = @import("tables.zig");
pub const alf_nt = @import("alf_nt.zig");
pub const fpe = @import("fpe.zig");
pub const alf_small = @import("alf_small.zig");
pub const alf_16t = @import("alf_16t.zig");
pub const alf_int = @import("alf_int.zig");
pub const alf_l = @import("alf_l.zig");
pub const ktm = @import("ktm.zig");
pub const prng = @import("prng.zig");

pub const Block = alf_nt.Block;

test {
    std.testing.refAllDecls(@This());
    _ = @import("kat_test.zig");
}
