//! The ALF family of format-preserving ciphers, built on AES rounds.
//!
//! Start here:
//!
//! * `Alf` encrypts one integer in [0, q), for any q up to 2^144.
//! * `AlfL` encrypts a vector of 16-bit symbols, each with its own modulus.
//!
//! Both pick the right cipher for the size of the domain.
//! The pieces they are made of are in `core`.

/// Encryption of one integer.
pub const Alf = @import("alf_int.zig").Alf;

/// Encryption of a vector of symbols.
pub const AlfL = @import("alf_l.zig").AlfL;

pub const errors = @import("errors.zig");

/// Core functions, that should rarely be used directly by applications.
pub const core = struct {
    /// ALF-0 and ALF-1-t, for q up to 2^15.
    pub const alf_small = @import("alf_small.zig");
    /// ALF-n-t, for 16 to 127 bits.
    pub const alf_nt = @import("alf_nt.zig");
    /// ALF-16-t, for 128 to 144 bits.
    pub const alf_16t = @import("alf_16t.zig");
    /// Turns the key and the tweak into round keys.
    pub const ktm = @import("ktm.zig");
    /// The keystream used for long vectors.
    pub const prng = @import("prng.zig");
    /// The constants of ALF-n-t.
    pub const tables = @import("tables.zig");
};

test {
    _ = Alf;
    _ = AlfL;

    _ = core.alf_small;
    _ = core.alf_nt;
    _ = core.alf_16t;
    _ = core.ktm;
    _ = core.prng;
    _ = core.tables;

    _ = @import("kat_test.zig");
}
