use std::error::Error;
use std::fmt;

use crate::frame::FrameKind;
use crate::state::{ConnectionEvent, ConnectionLifecycle, ConnectionState};

/// A frame kind rejected by the connection lifecycle policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FramePolicyError {
    pub(crate) state: ConnectionState,
    pub(crate) kind: FrameKind,
}

impl fmt::Display for FramePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frame kind {:?} is forbidden in state {:?}",
            self.kind, self.state
        )
    }
}

impl Error for FramePolicyError {}

impl ConnectionLifecycle {
    /// Checks whether a frame kind is permitted in the current state.
    ///
    /// This checks lifecycle ordering only. It does not validate a
    /// control message, authenticate a peer, or verify ciphertext.
    ///
    /// A rejection permanently closes this lifecycle.
    pub(crate) fn check_frame_kind(&mut self, kind: FrameKind) -> Result<(), FramePolicyError> {
        use ConnectionState as State;

        let state = self.state();

        let allowed = matches!(
            (state, kind),
            (
                State::Negotiating | State::Authenticating | State::EstablishingKeys,
                FrameKind::Control
            ) | (State::ConfirmingKeys | State::Ready, FrameKind::Encrypted)
        );

        if allowed {
            return Ok(());
        }

        // Close is valid from every state, including Closed.
        self.advance(ConnectionEvent::Close)
            .expect("closing a lifecycle must always succeed");

        Err(FramePolicyError { state, kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: [ConnectionState; 7] = [
        ConnectionState::AwaitingTls,
        ConnectionState::Negotiating,
        ConnectionState::Authenticating,
        ConnectionState::EstablishingKeys,
        ConnectionState::ConfirmingKeys,
        ConnectionState::Ready,
        ConnectionState::Closed,
    ];

    fn lifecycle_at(state: ConnectionState) -> ConnectionLifecycle {
        let mut lifecycle = ConnectionLifecycle::new();

        if state == ConnectionState::Closed {
            lifecycle.advance(ConnectionEvent::Close).unwrap();
            return lifecycle;
        }

        for event in [
            ConnectionEvent::TlsEstablished,
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
            ConnectionEvent::KeyMaterialInstalled,
            ConnectionEvent::KeysConfirmed,
        ] {
            if lifecycle.state() == state {
                return lifecycle;
            }

            lifecycle.advance(event).unwrap();
        }

        assert_eq!(lifecycle.state(), state);
        lifecycle
    }

    #[test]
    fn control_frames_are_allowed_only_during_setup() {
        for state in STATES {
            let mut lifecycle = lifecycle_at(state);

            let should_allow = matches!(
                state,
                ConnectionState::Negotiating
                    | ConnectionState::Authenticating
                    | ConnectionState::EstablishingKeys
            );

            let result = lifecycle.check_frame_kind(FrameKind::Control);

            assert_eq!(result.is_ok(), should_allow, "state: {state:?}");

            if should_allow {
                assert_eq!(lifecycle.state(), state);
            } else {
                assert_eq!(
                    result,
                    Err(FramePolicyError {
                        state,
                        kind: FrameKind::Control,
                    })
                );
                assert_eq!(lifecycle.state(), ConnectionState::Closed);
            }
        }
    }

    #[test]
    fn encrypted_frames_are_allowed_only_for_confirmation_or_ready() {
        for state in STATES {
            let mut lifecycle = lifecycle_at(state);

            let result = lifecycle.check_frame_kind(FrameKind::Encrypted);

            let should_allow = matches!(
                state,
                ConnectionState::ConfirmingKeys | ConnectionState::Ready
            );

            if should_allow {
                assert_eq!(result, Ok(()));
                assert_eq!(lifecycle.state(), state);
            } else {
                assert_eq!(
                    result,
                    Err(FramePolicyError {
                        state,
                        kind: FrameKind::Encrypted,
                    })
                );
                assert_eq!(lifecycle.state(), ConnectionState::Closed);
            }
        }
    }

    #[test]
    fn rejection_prevents_later_frames() {
        let mut lifecycle = lifecycle_at(ConnectionState::Negotiating);

        assert!(lifecycle.check_frame_kind(FrameKind::Encrypted).is_err());

        assert!(lifecycle.check_frame_kind(FrameKind::Control).is_err());

        assert_eq!(lifecycle.state(), ConnectionState::Closed);
    }

    #[test]
    fn error_describes_the_original_state() {
        let mut lifecycle = ConnectionLifecycle::new();

        let error = lifecycle
            .check_frame_kind(FrameKind::Encrypted)
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "frame kind Encrypted is forbidden in state AwaitingTls"
        );
    }
}
