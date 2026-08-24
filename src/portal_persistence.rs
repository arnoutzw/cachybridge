//! Opt-in portal permission persistence shared by InputCapture and RemoteDesktop.
//!
//! Restore tokens are single-use secrets. This module deliberately performs no
//! storage; callers must replace or clear their saved token after every start.

use std::fmt;

use thiserror::Error;

const MAX_RESTORE_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct RestoreToken(String);

impl RestoreToken {
    pub fn new(value: impl Into<String>) -> Result<Self, PersistenceError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PersistenceError::EmptyToken);
        }
        if value.len() > MAX_RESTORE_TOKEN_BYTES {
            return Err(PersistenceError::TokenTooLong(value.len()));
        }
        if value.contains('\0') {
            return Err(PersistenceError::EmbeddedNul);
        }
        Ok(Self(value))
    }

    /// Borrow the secret for a portal call or secure configuration backend.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn into_secret(self) -> String {
        self.0
    }
}

impl fmt::Debug for RestoreToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestoreToken([REDACTED])")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortalPersistence {
    enabled: bool,
    restore_token: Option<RestoreToken>,
}

impl PortalPersistence {
    /// Preserve the legacy behavior: no persistence and no restore attempt.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Persist permission until explicitly revoked, optionally restoring a
    /// previous grant. Invalid/withdrawn tokens are ignored by the portal and
    /// cause the normal consent dialog to be shown.
    pub fn persistent(restore_token: Option<RestoreToken>) -> Self {
        Self {
            enabled: true,
            restore_token,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn restore_token(&self) -> Option<&RestoreToken> {
        self.restore_token.as_ref()
    }

    pub(crate) fn persist_mode(&self) -> u32 {
        if self.enabled {
            2
        } else {
            0
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PersistenceError {
    #[error("restore token is empty")]
    EmptyToken,
    #[error("restore token is too long ({0} bytes)")]
    TokenTooLong(usize),
    #[error("restore token contains an embedded NUL")]
    EmbeddedNul,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_is_safe_off_by_default() {
        let settings = PortalPersistence::default();
        assert!(!settings.is_enabled());
        assert_eq!(settings.persist_mode(), 0);
        assert!(settings.restore_token().is_none());
    }

    #[test]
    fn persistent_mode_holds_a_redacted_single_use_token() {
        let token = RestoreToken::new("portal-secret").unwrap();
        let settings = PortalPersistence::persistent(Some(token));
        assert!(settings.is_enabled());
        assert_eq!(settings.persist_mode(), 2);
        assert_eq!(
            settings.restore_token().unwrap().expose_secret(),
            "portal-secret"
        );
        assert_eq!(
            format!("{:?}", settings.restore_token().unwrap()),
            "RestoreToken([REDACTED])"
        );
        assert!(!format!("{settings:?}").contains("portal-secret"));
    }

    #[test]
    fn malformed_tokens_are_rejected_before_dbus() {
        assert_eq!(RestoreToken::new(""), Err(PersistenceError::EmptyToken));
        assert_eq!(
            RestoreToken::new("bad\0token"),
            Err(PersistenceError::EmbeddedNul)
        );
        assert!(matches!(
            RestoreToken::new("x".repeat(MAX_RESTORE_TOKEN_BYTES + 1)),
            Err(PersistenceError::TokenTooLong(_))
        ));
    }
}
