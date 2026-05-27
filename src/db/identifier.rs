use std::fmt;
use std::str::FromStr;

/// Maximum byte length for a Postgres identifier.
pub const MAX_PG_IDENTIFIER_BYTES: usize = 63;

/// A validated unqualified Postgres identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PgIdentifier(String);

/// A validated Postgres schema name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PgSchemaName(PgIdentifier);

/// A validated table name with an optional schema.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PgQualifiedTableName {
    schema: Option<PgSchemaName>,
    table: PgIdentifier,
}

/// Display wrapper that emits a quoted Postgres identifier.
#[derive(Clone, Copy, Debug)]
pub struct QuotedPgIdentifier<'a>(&'a PgIdentifier);

/// Display wrapper that emits a quoted Postgres qualified table name.
#[derive(Clone, Copy, Debug)]
pub struct QuotedPgQualifiedTableName<'a>(&'a PgQualifiedTableName);

/// Error returned when a Postgres identifier is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidPgIdentifier {
    /// Identifier text must not be empty.
    Empty,
    /// Identifier text exceeded its maximum byte length.
    TooLong {
        /// Actual identifier byte length.
        actual: usize,
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The first identifier byte was not an ASCII letter or underscore.
    InvalidFirstByte {
        /// Invalid first byte.
        byte: u8,
    },
    /// A non-first identifier byte was not an ASCII letter, digit, or underscore.
    InvalidByte {
        /// Zero-based byte index where validation failed.
        index: usize,
        /// Invalid byte value.
        byte: u8,
    },
}

impl PgIdentifier {
    /// Validates and copies an unqualified Postgres identifier.
    pub fn new(input: impl AsRef<str>) -> Result<Self, InvalidPgIdentifier> {
        validate_pg_identifier(input.as_ref(), MAX_PG_IDENTIFIER_BYTES)?;
        Ok(Self(input.as_ref().to_owned()))
    }

    /// Returns the validated identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a display wrapper for quoted SQL generation.
    pub fn quoted(&self) -> QuotedPgIdentifier<'_> {
        QuotedPgIdentifier(self)
    }
}

impl PgSchemaName {
    /// Wraps a validated identifier as a schema name.
    pub fn new(identifier: PgIdentifier) -> Self {
        Self(identifier)
    }

    /// Validates and copies a Postgres schema name.
    pub fn from_identifier_text(input: impl AsRef<str>) -> Result<Self, InvalidPgIdentifier> {
        Ok(Self(PgIdentifier::new(input)?))
    }

    /// Returns the schema identifier.
    pub fn identifier(&self) -> &PgIdentifier {
        &self.0
    }

    /// Returns the validated schema text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PgQualifiedTableName {
    /// Creates a table name from validated schema and table parts.
    pub fn new(schema: Option<PgSchemaName>, table: PgIdentifier) -> Self {
        Self { schema, table }
    }

    /// Validates and copies an unqualified table name.
    pub fn unqualified(table: impl AsRef<str>) -> Result<Self, InvalidPgIdentifier> {
        Ok(Self::new(None, PgIdentifier::new(table)?))
    }

    /// Validates and copies a schema-qualified table name.
    pub fn with_schema(
        schema: impl AsRef<str>,
        table: impl AsRef<str>,
    ) -> Result<Self, InvalidPgIdentifier> {
        Ok(Self::new(
            Some(PgSchemaName::from_identifier_text(schema)?),
            PgIdentifier::new(table)?,
        ))
    }

    /// Returns the optional schema name.
    pub fn schema(&self) -> Option<&PgSchemaName> {
        self.schema.as_ref()
    }

    /// Returns the table identifier.
    pub fn table(&self) -> &PgIdentifier {
        &self.table
    }

    /// Returns a display wrapper for quoted SQL generation.
    pub fn quoted(&self) -> QuotedPgQualifiedTableName<'_> {
        QuotedPgQualifiedTableName(self)
    }
}

impl fmt::Display for QuotedPgIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.as_str())
    }
}

impl fmt::Display for QuotedPgQualifiedTableName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(schema) = self.0.schema() {
            write!(
                f,
                "{}.{}",
                schema.identifier().quoted(),
                self.0.table().quoted()
            )
        } else {
            self.0.table().quoted().fmt(f)
        }
    }
}

pub(crate) fn pg_table_names_could_resolve_to_same_relation(
    left: &PgQualifiedTableName,
    right: &PgQualifiedTableName,
) -> bool {
    if left.table() != right.table() {
        return false;
    }
    match (left.schema(), right.schema()) {
        (Some(left_schema), Some(right_schema)) => left_schema == right_schema,
        _ => true,
    }
}

pub(crate) fn pg_table_name_set_could_contain_same_relation(
    table_names: &[&PgQualifiedTableName],
) -> bool {
    for (index, left) in table_names.iter().enumerate() {
        for right in &table_names[index + 1..] {
            if pg_table_names_could_resolve_to_same_relation(left, right) {
                return true;
            }
        }
    }
    false
}

impl fmt::Display for InvalidPgIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Postgres identifier must not be empty"),
            Self::TooLong { actual, max } => {
                write!(f, "Postgres identifier is {actual} bytes, maximum is {max}")
            }
            Self::InvalidFirstByte { byte } => write!(
                f,
                "Postgres identifier first byte 0x{byte:02x} is not an ASCII letter or underscore"
            ),
            Self::InvalidByte { index, byte } => write!(
                f,
                "Postgres identifier byte 0x{byte:02x} at index {index} is not an ASCII letter, digit, or underscore"
            ),
        }
    }
}

impl std::error::Error for InvalidPgIdentifier {}

impl FromStr for PgIdentifier {
    type Err = InvalidPgIdentifier;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl FromStr for PgSchemaName {
    type Err = InvalidPgIdentifier;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_identifier_text(input)
    }
}

fn validate_pg_identifier(input: &str, max_len: usize) -> Result<(), InvalidPgIdentifier> {
    if input.is_empty() {
        return Err(InvalidPgIdentifier::Empty);
    }
    if input.len() > max_len {
        return Err(InvalidPgIdentifier::TooLong {
            actual: input.len(),
            max: max_len,
        });
    }

    let bytes = input.as_bytes();
    let first = bytes[0];
    if !is_pg_identifier_first_byte(first) {
        return Err(InvalidPgIdentifier::InvalidFirstByte { byte: first });
    }

    for (index, byte) in bytes.iter().copied().enumerate().skip(1) {
        if !is_pg_identifier_trailing_byte(byte) {
            return Err(InvalidPgIdentifier::InvalidByte { index, byte });
        }
    }

    Ok(())
}

fn is_pg_identifier_first_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_pg_identifier_trailing_byte(byte: u8) -> bool {
    is_pg_identifier_first_byte(byte) || byte.is_ascii_digit()
}
