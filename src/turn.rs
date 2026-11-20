use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnState {
    ClientCanSend,
    ClientAwaitingResponse,
    ServerAwaitingRequest,
    ServerMustRespond,
    Closed,
}

/// Events emitted only after the corresponding operation succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnEvent {
    RequestSent,
    ResponseReceived,
    RequestReceived,
    ResponseSent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TurnError {
    pub(crate) state: TurnState,
    pub(crate) event: TurnEvent,
}

impl fmt::Display for TurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "event {:?} is invalid in application turn {:?}",
            self.event, self.state
        )
    }
}

impl Error for TurnError {}

/// Sequential application-exchange state for one endpoint.
///
/// Not Clone or Copy.
#[derive(Debug)]
pub(crate) struct Exchange {
    state: TurnState,
}

impl Exchange {
    pub(crate) fn client() -> Self {
        Self {
            state: TurnState::ClientCanSend,
        }
    }

    pub(crate) fn server() -> Self {
        Self {
            state: TurnState::ServerAwaitingRequest,
        }
    }

    pub(crate) fn state(&self) -> TurnState {
        self.state
    }

    pub(crate) fn close(&mut self) {
        self.state = TurnState::Closed;
    }

    /// Commits a successful operation.
    ///
    /// Invalid transitions permanently close this exchange.
    pub(crate) fn advance(&mut self, event: TurnEvent) -> Result<(), TurnError> {
        use TurnEvent as Event;
        use TurnState as State;

        self.state = match (self.state, event) {
            (State::ClientCanSend, Event::RequestSent) => State::ClientAwaitingResponse,
            (State::ClientAwaitingResponse, Event::ResponseReceived) => State::ClientCanSend,
            (State::ServerAwaitingRequest, Event::RequestReceived) => State::ServerMustRespond,
            (State::ServerMustRespond, Event::ResponseSent) => State::ServerAwaitingRequest,
            (state, event) => {
                self.close();
                return Err(TurnError { state, event });
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: [TurnState; 5] = [
        TurnState::ClientCanSend,
        TurnState::ClientAwaitingResponse,
        TurnState::ServerAwaitingRequest,
        TurnState::ServerMustRespond,
        TurnState::Closed,
    ];

    const EVENTS: [TurnEvent; 4] = [
        TurnEvent::RequestSent,
        TurnEvent::ResponseReceived,
        TurnEvent::RequestReceived,
        TurnEvent::ResponseSent,
    ];

    #[test]
    fn client_starts_with_permission_to_send() {
        assert_eq!(Exchange::client().state(), TurnState::ClientCanSend);
    }

    #[test]
    fn server_starts_waiting_for_a_request() {
        assert_eq!(Exchange::server().state(), TurnState::ServerAwaitingRequest);
    }

    #[test]
    fn supports_repeated_sequential_exchanges() {
        let mut client = Exchange::client();
        let mut server = Exchange::server();

        for _ in 0..10 {
            client.advance(TurnEvent::RequestSent).unwrap();
            server.advance(TurnEvent::RequestReceived).unwrap();

            assert_eq!(client.state(), TurnState::ClientAwaitingResponse);
            assert_eq!(server.state(), TurnState::ServerMustRespond);

            server.advance(TurnEvent::ResponseSent).unwrap();
            client.advance(TurnEvent::ResponseReceived).unwrap();

            assert_eq!(client.state(), TurnState::ClientCanSend);
            assert_eq!(server.state(), TurnState::ServerAwaitingRequest);
        }
    }

    #[test]
    fn transition_matrix_rejects_every_invalid_event() {
        for state in STATES {
            for event in EVENTS {
                let expected = match (state, event) {
                    (TurnState::ClientCanSend, TurnEvent::RequestSent) => {
                        Some(TurnState::ClientAwaitingResponse)
                    }
                    (TurnState::ClientAwaitingResponse, TurnEvent::ResponseReceived) => {
                        Some(TurnState::ClientCanSend)
                    }
                    (TurnState::ServerAwaitingRequest, TurnEvent::RequestReceived) => {
                        Some(TurnState::ServerMustRespond)
                    }
                    (TurnState::ServerMustRespond, TurnEvent::ResponseSent) => {
                        Some(TurnState::ServerAwaitingRequest)
                    }
                    _ => None,
                };

                let mut exchange = Exchange { state };
                let result = exchange.advance(event);

                match expected {
                    Some(next) => {
                        assert_eq!(result, Ok(()));
                        assert_eq!(exchange.state(), next);
                    }
                    None => {
                        assert_eq!(result, Err(TurnError { state, event }));
                        assert_eq!(exchange.state(), TurnState::Closed);
                    }
                }
            }
        }
    }

    #[test]
    fn closing_is_idempotent_and_prevents_restart() {
        for state in STATES {
            let mut exchange = Exchange { state };

            exchange.close();
            exchange.close();

            assert_eq!(exchange.state(), TurnState::Closed);

            for event in EVENTS {
                assert!(exchange.advance(event).is_err());
                assert_eq!(exchange.state(), TurnState::Closed);
            }
        }
    }

    #[test]
    fn error_reports_original_turn_and_event() {
        let mut exchange = Exchange::server();

        let error = exchange.advance(TurnEvent::ResponseSent).unwrap_err();

        assert_eq!(
            error.to_string(),
            "event ResponseSent is invalid in application turn ServerAwaitingRequest"
        );
    }
}
