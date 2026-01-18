// Copyright 2025 The dcSCTP Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(test)]
mod tests {
    use crate::api::DcSctpSocket;
    use crate::api::ErrorKind;
    use crate::api::Options;
    use crate::api::SocketEvent;
    use crate::api::SocketState;
    use crate::packet::chunk::Chunk;
    use crate::packet::cookie_echo_chunk::CookieEchoChunk;
    use crate::packet::sctp_packet::SctpPacket;
    use crate::packet::sctp_packet::SctpPacketBuilder;
    use crate::socket::Socket;
    use crate::socket::state_cookie::StateCookie;
    use crate::testing::event_helpers::expect_no_event;
    use crate::testing::event_helpers::expect_on_connected;
    use crate::testing::event_helpers::expect_on_error;
    use crate::testing::event_helpers::expect_sent_packet;

    fn default_options() -> Options {
        Options::default()
    }

    fn connect_sockets(socket_a: &mut Socket, socket_z: &mut Socket) {
        socket_a.connect();
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
    }

    #[test]
    fn restart_detected() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // A "crashes" and restarts as A_Prime.
        let mut socket_a_prime = Socket::new("A_Prime", &options);
        socket_a_prime.connect();

        // A' -> INIT -> Z
        let init_packet = expect_sent_packet!(socket_a_prime.poll_event());
        socket_z.handle_input(&init_packet);

        // Z -> INIT_ACK -> A'
        // This INIT_ACK should contain the restart cookie logic (same tie_tag as A).
        let init_ack_packet = expect_sent_packet!(socket_z.poll_event());
        socket_a_prime.handle_input(&init_ack_packet);

        // A' -> COOKIE_ECHO -> Z
        let cookie_echo_packet = expect_sent_packet!(socket_a_prime.poll_event());
        socket_z.handle_input(&cookie_echo_packet);

        // Z should detect restart.
        let event = socket_z.poll_event().unwrap();
        assert!(matches!(event, SocketEvent::OnConnectionRestarted()));
        expect_on_connected!(socket_z.poll_event());

        // Z -> COOKIE_ACK -> A'
        let cookie_ack_packet = expect_sent_packet!(socket_z.poll_event());
        socket_a_prime.handle_input(&cookie_ack_packet);
        expect_on_connected!(socket_a_prime.poll_event());
    }

    #[test]
    fn discard_packet_on_tie_tag_zero_and_vtag_mismatch() {
        // CookieResolution::Discard:
        // v_tag_mismatch && !peer_tag_mismatch && cookie.tie_tag == 0

        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let z_tag = socket_z.verification_tag();
        let a_tag = socket_a.verification_tag();

        // Create a cookie where:
        // peer_tag = a_tag (Matches Z's TCB peer tag for A)
        // my_tag = z_tag (Matches Z's TCB my tag)
        // tie_tag = 0
        let cookie = StateCookie {
            peer_tag: a_tag,
            my_tag: z_tag,
            peer_initial_tsn: crate::types::Tsn(0),
            my_initial_tsn: crate::types::Tsn(0),
            a_rwnd: 1000,
            tie_tag: 0,
            capabilities: crate::socket::capabilities::Capabilities::default(),
        };

        // Send COOKIE_ECHO with a mismatching verification tag.
        // Z expects `z_tag` as verification tag in the header.
        // We send `z_tag + 1`.
        let packet = SctpPacketBuilder::new(
            z_tag.wrapping_add(1),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::CookieEcho(CookieEchoChunk { cookie: cookie.serialize() }))
        .build();

        socket_z.handle_input(&packet);

        // Expect SILENT DISCARD.
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn invalid_tag() {
        // CookieResolution::InvalidTag (Fallback)
        // e.g. v_tag_mismatch && peer_tag_mismatch && cookie.tie_tag != tcb.tie_tag

        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let z_tag = socket_z.verification_tag();
        let a_tag = socket_a.verification_tag();

        // Create a cookie with:
        // peer_tag = a_tag + 1 (Mismatch)
        // my_tag = z_tag (Match)
        // tie_tag = 12345 (Random)
        let cookie = StateCookie {
            peer_tag: a_tag.wrapping_add(1),
            my_tag: z_tag,
            peer_initial_tsn: crate::types::Tsn(0),
            my_initial_tsn: crate::types::Tsn(0),
            a_rwnd: 1000,
            tie_tag: 12345,
            capabilities: crate::socket::capabilities::Capabilities::default(),
        };

        // Send COOKIE_ECHO with a mismatching verification tag.
        // Z expects `z_tag`.
        let packet = SctpPacketBuilder::new(
            z_tag.wrapping_add(1),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::CookieEcho(CookieEchoChunk { cookie: cookie.serialize() }))
        .build();

        socket_z.handle_input(&packet);

        // Expect Error.
        assert_eq!(expect_on_error!(socket_z.poll_event()), ErrorKind::ParseFailed);
    }

    #[test]
    fn duplicate_cookie_echo_maintains_existing() {
        // CookieResolution::MaintainExisting
        // !v_tag_mismatch && !peer_tag_mismatch
        // State is Established.

        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        // Manually connect to capture COOKIE_ECHO
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // Z -> INIT_ACK -> A
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        let cookie_echo_packet = expect_sent_packet!(socket_a.poll_event());
        socket_z.handle_input(&cookie_echo_packet);
        expect_on_connected!(socket_z.poll_event());
        // Z -> COOKIE_ACK -> A
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());

        // Now replay the COOKIE_ECHO to Z.
        socket_z.handle_input(&cookie_echo_packet);

        // Z should respond with COOKIE_ACK.
        let response = expect_sent_packet!(socket_z.poll_event());
        let response = SctpPacket::from_bytes(&response, &options).unwrap();
        assert!(matches!(response.chunks[0], Chunk::CookieAck(_)));

        // And Z should still be Established.
        assert_eq!(socket_z.state(), SocketState::Connected);
    }
}
