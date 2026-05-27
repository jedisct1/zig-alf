//! ALF cipher family: AES-NI-based length- and format-preserving encryption.
//!
//! The umbrella module re-exports each variant.
//!
//! * `alf_nt` — main length-preserving block cipher of width (8n + t) bits
//!   for n ∈ [2, 15], t ∈ [0, 7] (16..127 bits).
//! * `fpe` — cycle-sliding wrapper turning `alf_nt` into a format-preserving
//!   cipher for any modulus Q ∈ (2^15, 2^127].
//! * `alf_small` — ALF-0 (Q ∈ [2, 256]) and ALF-1-t (9..15 bits).
//! * `alf_16t` — ALF-16-t (128..144 bits, Q up to 2^144).
//! * `alf_l` — vector cipher for arbitrary-length plaintexts with per-position
//!   moduli, built on ALF-16-t plus a Rocca-S-based ModPRNG keystream.
//! * `ktm` — Key-Tweak Management (SMAC-3/4 based round-key generator).
//! * `prng` — BinPRNG / ModPRNG used by ALF-L.

const std = @import("std");

pub const tables = @import("tables.zig");
pub const alf_nt = @import("alf_nt.zig");
pub const fpe = @import("fpe.zig");
pub const alf_small = @import("alf_small.zig");
pub const alf_16t = @import("alf_16t.zig");
pub const alf_l = @import("alf_l.zig");
pub const ktm = @import("ktm.zig");
pub const prng = @import("prng.zig");

pub const Block = alf_nt.Block;

test {
    std.testing.refAllDecls(@This());
}
