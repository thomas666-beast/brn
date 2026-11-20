use std::error::Error;
use std::fmt;

/// The internal lifecycle of a single BRN connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    AwaitingTls,
    Negotiating,
    Authenticating,
    EstablishingKeys,
    ConfirmingKeys,
    Ready,
    Closed,
}

/// An event emitted after the corresponding operation succeeds.
///
/// This is internal: callers must not be able to claim that a security
/// operation succeeded without the connection implementation checking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionEvent {
    TlsEstablished,
    VersionAccepted,
    ClientAuthenticated,
    KeyMaterialInstalled,
    KeysConfirmed,
    Close,
}

/// A rejected lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransitionError {
    pub(crate) state: ConnectionState,
    pub(crate) event: ConnectionEvent,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "event {:?} is invalid in state {:?}",
            self.event, self.state
        )
    }
}

impl Error for TransitionError {}

/// Tracks lifecycle ordering without performing networking or cryptography.
#[derive(Debug)]
pub(crate) struct ConnectionLifecycle {
    state: ConnectionState,
}

impl ConnectionLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: ConnectionState::AwaitingTls,
        }
    }

    pub(crate) fn state(&self) -> ConnectionState {
        self.state
    }

    pub(crate) fn advance(&mut self, event: ConnectionEvent) -> Result<(), TransitionError> {
        use ConnectionEvent as Event;
        use ConnectionState as State;

        let next = match (self.state, event) {
            (_, Event::Close) => State::Closed,
            (State::AwaitingTls, Event::TlsEstablished) => State::Negotiating,
            (State::Negotiating, Event::VersionAccepted) => State::Authenticating,
            (State::Authenticating, Event::ClientAuthenticated) => State::EstablishingKeys,
            (State::EstablishingKeys, Event::KeyMaterialInstalled) => State::ConfirmingKeys,
            (State::ConfirmingKeys, Event::KeysConfirmed) => State::Ready,
            (state, event) => {
                self.state = State::Closed;
                return Err(TransitionError { state, event });
            }
        };

        self.state = next;
        Ok(())
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

    const SUCCESS_EVENTS: [ConnectionEvent; 5] = [
        ConnectionEvent::TlsEstablished,
        ConnectionEvent::VersionAccepted,
        ConnectionEvent::ClientAuthenticated,
        ConnectionEvent::KeyMaterialInstalled,
        ConnectionEvent::KeysConfirmed,
    ];

    #[test]
    fn new_connection_awaits_tls() {
        let lifecycle = ConnectionLifecycle::new();

        assert_eq!(lifecycle.state(), ConnectionState::AwaitingTls);
    }

    #[test]
    fn valid_sequence_reaches_ready() {
        let mut lifecycle = ConnectionLifecycle::new();

        for (index, event) in SUCCESS_EVENTS.into_iter().enumerate() {
            assert_eq!(lifecycle.advance(event), Ok(()));
            assert_eq!(lifecycle.state(), STATES[index + 1]);
        }
    }

    #[test]
    fn close_is_allowed_from_every_state() {
        for state in STATES {
            let mut lifecycle = ConnectionLifecycle { state };

            assert_eq!(lifecycle.advance(ConnectionEvent::Close), Ok(()));
            assert_eq!(lifecycle.state(), ConnectionState::Closed);
        }
    }

    #[test]
    fn every_invalid_success_event_closes_the_connection() {
        for (state_index, state) in STATES.into_iter().enumerate() {
            for (event_index, event) in SUCCESS_EVENTS.into_iter().enumerate() {
                if state_index == event_index {
                    continue;
                }

                let mut lifecycle = ConnectionLifecycle { state };

                assert_eq!(
                    lifecycle.advance(event),
                    Err(TransitionError { state, event })
                );
                assert_eq!(lifecycle.state(), ConnectionState::Closed);
            }
        }
    }

    #[test]
    fn closed_connection_cannot_restart() {
        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle.advance(ConnectionEvent::Close).unwrap();

        for event in SUCCESS_EVENTS {
            assert!(lifecycle.advance(event).is_err());
            assert_eq!(lifecycle.state(), ConnectionState::Closed);
        }
    }

    #[test]
    fn error_identifies_the_original_state_and_event() {
        let mut lifecycle = ConnectionLifecycle::new();

        let error = lifecycle
            .advance(ConnectionEvent::KeysConfirmed)
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "event KeysConfirmed is invalid in state AwaitingTls"
        );
    }
}
