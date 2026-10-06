# Reference test vectors

`testvec.hpp` is a plain copy of `refcode/testvec.hpp` from the ALF reference implementation:
https://github.com/0NG/ALF-tools, commit e8089776dc.

It is under the MIT license, see `LICENSE` next to it.

`src/kat_test.zig` reads the lines that look like `/*[T0]*/ { ... },`.
Each one is a test case, with these numbers in order:

- the kind of test, its index, and the number of symbols N
- for S and C vectors, the shared modulus minus one
- for D vectors, where the moduli start in the table of distinct moduli (0xffff otherwise)
- for T vectors, Q - 1 as three 64-bit words
- the key state after KeyInit (48 bytes)
- key material for encryption, then for decryption (64 bytes each)
- the first 32 bytes of the result after 1, 5 and 999 encryptions of zero

To update the vectors, replace the file with the new upstream one and run `zig build test`.
If the number of vectors changed, the counts at the end of each test need to follow.
