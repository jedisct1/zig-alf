/// The modulus is outside of the range the cipher supports
pub const ModulusOutOfRangeError = error{ModulusOutOfRange};

/// The integer to encrypt or decrypt is not below the modulus
pub const ValueOutOfRangeError = error{ValueOutOfRange};

/// A symbol of a vector is not below its modulus
pub const SymbolOutOfRangeError = error{SymbolOutOfRange};

/// The vector to encrypt or decrypt has no symbols
pub const EmptyInputError = error{EmptyInput};

/// Any error an ALF function can return
pub const Error = ModulusOutOfRangeError || ValueOutOfRangeError || SymbolOutOfRangeError || EmptyInputError;
