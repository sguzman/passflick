use std::fmt;

pub const MIN_LENGTH: usize = 12;
pub const MAX_LENGTH: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseError {
    TooShort,
    TooLong,
    Mismatch,
}

impl fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "New vault passphrase must have at least {MIN_LENGTH} characters"),
            Self::TooLong => write!(f, "New vault passphrase exceeds the {MAX_LENGTH}-character limit"),
            Self::Mismatch => write!(f, "Passphrases do not match"),
        }
    }
}

impl std::error::Error for PassphraseError {}

/// Only new vault creation is subject to this policy. Existing vaults always
/// accept their original passphrases, including values from older releases.
pub fn validate_new(passphrase: &str, confirmation: &str) -> Result<(), PassphraseError> {
    let length = passphrase.chars().count();
    if length < MIN_LENGTH {
        return Err(PassphraseError::TooShort);
    }
    if length > MAX_LENGTH {
        return Err(PassphraseError::TooLong);
    }
    if passphrase != confirmation {
        return Err(PassphraseError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_length_is_enforced_without_character_class_rules() {
        assert_eq!(validate_new("short", "short"), Err(PassphraseError::TooShort));
        assert!(validate_new("twelve chars", "twelve chars").is_ok());
        assert!(validate_new("correct horse battery staple", "correct horse battery staple").is_ok());
    }

    #[test]
    fn confirmation_must_match_exactly() {
        assert_eq!(
            validate_new("fictional long phrase", "fictional LONG phrase"),
            Err(PassphraseError::Mismatch)
        );
        assert_eq!(
            validate_new("fictional long phrase ", "fictional long phrase"),
            Err(PassphraseError::Mismatch)
        );
    }

    #[test]
    fn unicode_length_and_upper_limit_are_bounded() {
        let unicode = "猫".repeat(MIN_LENGTH);
        assert!(validate_new(&unicode, &unicode).is_ok());
        let enormous = "a".repeat(MAX_LENGTH + 1);
        assert_eq!(validate_new(&enormous, &enormous), Err(PassphraseError::TooLong));
    }
}
