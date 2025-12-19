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

use dcsctp::api::DcSctpSocket as DcSctpSocketTrait;
use dcsctp::api::Message as DcSctpMessage;
use dcsctp::api::Options;
use dcsctp::api::PpId as DcSctpPpId;
use dcsctp::api::SendOptions;
use dcsctp::api::SendStatus as DcSctpSendStatus;
use dcsctp::api::SocketEvent as DcSctpSocketEvent;
use dcsctp::api::SocketState as DcSctpSocketState;
use dcsctp::api::StreamId as DcSctpStreamId;
use std::time::Instant;

const MAX_LIFETIME_MS: u64 = 3600 * 1000;

#[cxx::bridge(namespace = "dcsctp_cxx")]
mod ffi {
    #[derive(Debug, Default)]
    struct Message {
        stream_id: u16,
        ppid: u32,
        payload: Vec<u8>,
    }

    #[derive(Debug)]
    struct SendOptions {
        unordered: bool,
        lifetime_ms: u64,
        max_retransmissions: u16,
        lifecycle_id: u64,
    }

    #[derive(Debug)]
    enum SocketState {
        Closed,
        Connecting,
        Connected,
        ShuttingDown,
    }

    #[derive(Debug)]
    enum EventType {
        Nothing,
        OnConnected,
        SendPacket,
        Other,
    }

    struct Event {
        event_type: EventType,
        packet: Vec<u8>,
    }

    #[derive(Debug, PartialEq)]
    enum SendStatus {
        Success,
        ErrorMessageEmpty,
        ErrorMessageTooLarge,
        ErrorResourceExhaustion,
        ErrorShuttingDown,
    }

    extern "Rust" {
        type DcSctpSocket;

        fn version() -> String;
        fn new_socket() -> *mut DcSctpSocket;
        unsafe fn delete_socket(socket: *mut DcSctpSocket);
        fn state(socket: &DcSctpSocket) -> SocketState;
        fn connect(socket: &mut DcSctpSocket);
        fn handle_input(socket: &mut DcSctpSocket, data: &[u8]);
        fn poll_event(socket: &mut DcSctpSocket) -> Event;

        fn message_ready_count(socket: &DcSctpSocket) -> usize;
        fn get_next_message(socket: &mut DcSctpSocket) -> Message;
        fn new_send_options() -> SendOptions;
        fn send(
            socket: &mut DcSctpSocket,
            stream_id: u16,
            ppid: u32,
            payload: &[u8],
            options: &SendOptions,
        ) -> SendStatus;
    }
}

pub struct DcSctpSocket(Box<dyn DcSctpSocketTrait>);

fn version() -> String {
    dcsctp::version().to_string()
}

fn new_socket() -> *mut DcSctpSocket {
    let options = Options::default();
    let socket = dcsctp::new_socket("cxx-socket", Instant::now(), &options);
    let boxed_socket = Box::new(DcSctpSocket(socket));
    Box::into_raw(boxed_socket)
}

unsafe fn delete_socket(socket: *mut DcSctpSocket) {
    if !socket.is_null() {
        // SAFETY: The `socket` pointer must have been obtained from `new_socket` and must not be
        // used after this call.
        drop(Box::from_raw(socket));
    }
}

fn state(socket: &DcSctpSocket) -> ffi::SocketState {
    match socket.0.state() {
        DcSctpSocketState::Closed => ffi::SocketState::Closed,
        DcSctpSocketState::Connecting => ffi::SocketState::Connecting,
        DcSctpSocketState::Connected => ffi::SocketState::Connected,
        DcSctpSocketState::ShuttingDown => ffi::SocketState::ShuttingDown,
    }
}

fn connect(socket: &mut DcSctpSocket) {
    socket.0.connect();
}

fn handle_input(socket: &mut DcSctpSocket, data: &[u8]) {
    socket.0.handle_input(data)
}

fn poll_event(socket: &mut DcSctpSocket) -> ffi::Event {
    match socket.0.poll_event() {
        Some(DcSctpSocketEvent::SendPacket(p)) => {
            ffi::Event { event_type: ffi::EventType::SendPacket, packet: p }
        }
        Some(DcSctpSocketEvent::OnConnected()) => {
            ffi::Event { event_type: ffi::EventType::OnConnected, packet: Vec::new() }
        }
        Some(_) => ffi::Event { event_type: ffi::EventType::Other, packet: Vec::new() },
        None => ffi::Event { event_type: ffi::EventType::Nothing, packet: Vec::new() },
    }
}

fn message_ready_count(socket: &DcSctpSocket) -> usize {
    socket.0.messages_ready_count()
}

fn get_next_message(socket: &mut DcSctpSocket) -> ffi::Message {
    match socket.0.get_next_message() {
        Some(msg) => {
            ffi::Message { stream_id: msg.stream_id.0, ppid: msg.ppid.0, payload: msg.payload }
        }
        None => ffi::Message::default(),
    }
}

fn new_send_options() -> ffi::SendOptions {
    ffi::SendOptions {
        unordered: false,
        lifetime_ms: MAX_LIFETIME_MS,
        max_retransmissions: u16::MAX,
        lifecycle_id: 0,
    }
}

fn send(
    socket: &mut DcSctpSocket,
    stream_id: u16,
    ppid: u32,
    payload: &[u8],
    options: &ffi::SendOptions,
) -> ffi::SendStatus {
    let msg = DcSctpMessage::new(DcSctpStreamId(stream_id), DcSctpPpId(ppid), payload.to_vec());
    let rust_options = SendOptions {
        unordered: options.unordered,
        lifetime: if options.lifetime_ms < MAX_LIFETIME_MS {
            Some(std::time::Duration::from_millis(options.lifetime_ms))
        } else {
            None
        },
        max_retransmissions: if options.max_retransmissions != u16::MAX {
            Some(options.max_retransmissions)
        } else {
            None
        },
        lifecycle_id: dcsctp::api::LifecycleId::new(options.lifecycle_id),
    };
    match socket.0.send(msg, &rust_options) {
        DcSctpSendStatus::Success => ffi::SendStatus::Success,
        DcSctpSendStatus::ErrorMessageEmpty => ffi::SendStatus::ErrorMessageEmpty,
        DcSctpSendStatus::ErrorMessageTooLarge => ffi::SendStatus::ErrorMessageTooLarge,
        DcSctpSendStatus::ErrorResourceExhaustion => ffi::SendStatus::ErrorResourceExhaustion,
        DcSctpSendStatus::ErrorShuttingDown => ffi::SendStatus::ErrorShuttingDown,
    }
}
