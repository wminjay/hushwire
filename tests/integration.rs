//! In-memory end-to-end tests for the HushWire v3 cryptographic pipeline.

use std::process::Command;

use hushwire::auth::{self, MsgType, PacketKind, ParsedPacket};
use hushwire::noise::{self, NoiseError};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(unix)]
#[test]
fn cli_can_detach_from_a_transient_launcher_for_safe_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_hushwire"))
        .args([
            "--detach-session",
            "check",
            "--config",
            "tests/fixtures/macos-no-routes.toml",
        ])
        .output()
        .expect("run hushwire check in a detached session");

    assert!(
        output.status.success(),
        "detached check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("detached process from launcher session"),
        "detach event missing from stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn do_handshake(
    initiator_static: &StaticSecret,
    initiator_public: &PublicKey,
    responder_static: &StaticSecret,
    responder_public: &PublicKey,
    psk: &[u8; 32],
) -> (noise::Session, noise::Session) {
    let initiator = noise::initiator_start(initiator_static, responder_public, psk).unwrap();
    let (handshake_id, message, state) = initiator.into_parts();
    let responder = noise::responder_respond(
        responder_static,
        initiator_public,
        psk,
        handshake_id,
        &message,
    )
    .expect("responder accepts authenticated initiator static key");
    let initiator_session = noise::initiator_finalize(state, &responder.message)
        .expect("initiator authenticates responder and psk2");
    assert_eq!(initiator_session.session_id, responder.session.session_id);
    (initiator_session, responder.session)
}

fn random_session_pair(psk: &[u8; 32]) -> (noise::Session, noise::Session) {
    let (initiator_static, initiator_public) = gen_keypair();
    let (responder_static, responder_public) = gen_keypair();
    do_handshake(
        &initiator_static,
        &initiator_public,
        &responder_static,
        &responder_public,
        psk,
    )
}

#[test]
fn full_handshake_then_bidirectional_data_round_trip() {
    let (mut initiator, mut responder) = random_session_pair(&[0x42; 32]);

    let packet = initiator
        .encrypt(MsgType::Data, b"hello from initiator")
        .unwrap();
    assert_eq!(
        responder.decrypt_packet(&packet).unwrap(),
        (MsgType::Data, b"hello from initiator".to_vec())
    );

    let reply = responder
        .encrypt(MsgType::Data, b"hello from responder")
        .unwrap();
    assert_eq!(
        initiator.decrypt_packet(&reply).unwrap(),
        (MsgType::Data, b"hello from responder".to_vec())
    );
}

#[test]
fn keepalive_probe_and_ack_are_authenticated() {
    let (mut initiator, mut responder) = random_session_pair(&[0x43; 32]);

    let empty = initiator.encrypt(MsgType::Keepalive, b"").unwrap();
    assert_eq!(
        responder.decrypt_packet(&empty).unwrap(),
        (MsgType::Keepalive, Vec::new())
    );

    let probe = initiator
        .encrypt(MsgType::Keepalive, auth::KEEPALIVE_PROBE_PAYLOAD)
        .unwrap();
    assert_eq!(
        responder.decrypt_packet(&probe).unwrap(),
        (MsgType::Keepalive, auth::KEEPALIVE_PROBE_PAYLOAD.to_vec())
    );

    let acknowledgement = responder
        .encrypt(MsgType::Keepalive, auth::KEEPALIVE_ACK_PAYLOAD)
        .unwrap();
    assert_eq!(
        initiator.decrypt_packet(&acknowledgement).unwrap(),
        (MsgType::Keepalive, auth::KEEPALIVE_ACK_PAYLOAD.to_vec())
    );
}

#[test]
fn wrong_session_and_ciphertext_tampering_are_rejected() {
    let (mut sender, _) = random_session_pair(&[0x44; 32]);
    let (_, mut unrelated_receiver) = random_session_pair(&[0x45; 32]);

    let packet = sender.encrypt(MsgType::Data, b"secret").unwrap();
    assert!(matches!(
        unrelated_receiver.decrypt_packet(&packet),
        Err(NoiseError::WrongSession)
    ));

    // Route the packet to the unrelated session ID, then prove its unrelated
    // transport key still cannot authenticate the ciphertext.
    let mut wrong_key_packet = packet.clone();
    wrong_key_packet[2..auth::HANDSHAKE_HEADER_SIZE]
        .copy_from_slice(&unrelated_receiver.session_id);
    assert!(unrelated_receiver
        .decrypt_packet(&wrong_key_packet)
        .is_err());

    let (mut real_sender, mut real_receiver) = {
        let pair = random_session_pair(&[0x47; 32]);
        (pair.0, pair.1)
    };
    let mut tampered = real_sender
        .encrypt(MsgType::Data, b"authenticated")
        .unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(real_receiver.decrypt_packet(&tampered).is_err());

    // Keep this binding explicit so an accidental unused setup cannot mask a
    // type mismatch in this security regression test.
    assert_ne!(real_receiver.session_id, unrelated_receiver.session_id);
}

#[test]
fn replayed_packet_is_rejected_by_the_session() {
    let (mut initiator, mut responder) = random_session_pair(&[0x48; 32]);
    let packet = initiator.encrypt(MsgType::Data, b"once").unwrap();
    assert!(responder.decrypt_packet(&packet).is_ok());
    assert!(matches!(
        responder.decrypt_packet(&packet),
        Err(NoiseError::Replay)
    ));
}

#[test]
fn packet_header_exposes_only_routing_id_and_counter() {
    let (mut initiator, _) = random_session_pair(&[0x49; 32]);
    let packet = initiator.encrypt(MsgType::Data, b"payload").unwrap();
    let ParsedPacket::Transport {
        session_id,
        counter,
        ciphertext,
    } = auth::decode_packet(&packet).unwrap()
    else {
        panic!("transport packet");
    };
    assert_eq!(session_id, initiator.session_id);
    assert_eq!(counter, 0);
    assert!(!ciphertext
        .windows(b"payload".len())
        .any(|w| w == b"payload"));
}

#[test]
fn wrong_psk_fails_when_initiator_processes_the_response() {
    let (initiator_static, initiator_public) = gen_keypair();
    let (responder_static, responder_public) = gen_keypair();
    let initiator =
        noise::initiator_start(&initiator_static, &responder_public, &[0x50; 32]).unwrap();
    let (handshake_id, message, state) = initiator.into_parts();

    // IK authenticates the static initiator in msg1. In the psk2 pattern the
    // PSK is deliberately mixed in msg2, so the mismatch is detected here.
    let response = noise::responder_respond(
        &responder_static,
        &initiator_public,
        &[0x51; 32],
        handshake_id,
        &message,
    )
    .unwrap();
    assert!(noise::initiator_finalize(state, &response.message).is_err());
}

#[test]
fn handshake_packets_are_v3_framed_and_bound_to_their_identifier() {
    let (initiator_static, _) = gen_keypair();
    let (_, responder_public) = gen_keypair();
    let handshake =
        noise::initiator_start(&initiator_static, &responder_public, &[0x52; 32]).unwrap();
    let packet = auth::encode_handshake(
        PacketKind::HandshakeInit,
        &handshake.handshake_id,
        &handshake.message,
    );
    assert!(matches!(
        auth::decode_packet(&packet),
        Some(ParsedPacket::Handshake {
            kind: PacketKind::HandshakeInit,
            handshake_id,
            ..
        }) if handshake_id == handshake.handshake_id
    ));

    let mut old_version = packet;
    old_version[0] = 0x02;
    assert!(auth::decode_packet(&old_version).is_none());
}

#[test]
fn repeated_handshakes_produce_fresh_sessions() {
    let (initiator_static, initiator_public) = gen_keypair();
    let (responder_static, responder_public) = gen_keypair();
    let psk = [0x53; 32];
    let (first, _) = do_handshake(
        &initiator_static,
        &initiator_public,
        &responder_static,
        &responder_public,
        &psk,
    );
    let (second, _) = do_handshake(
        &initiator_static,
        &initiator_public,
        &responder_static,
        &responder_public,
        &psk,
    );
    assert_ne!(first.session_id, second.session_id);
}

#[test]
fn eighty_thousand_packets_have_unique_monotonic_nonces() {
    let (mut initiator, _) = random_session_pair(&[0x54; 32]);
    for expected in 0..80_000u64 {
        let packet = initiator.encrypt(MsgType::Data, b"x").unwrap();
        let Some(ParsedPacket::Transport { counter, .. }) = auth::decode_packet(&packet) else {
            panic!("transport packet");
        };
        assert_eq!(counter, expected);
    }
    assert_eq!(initiator.send_counter(), 80_000);
}

#[test]
fn one_server_static_key_supports_multiple_isolated_clients() {
    let (server_static, server_public) = gen_keypair();
    let (client_a_static, client_a_public) = gen_keypair();
    let (client_b_static, client_b_public) = gen_keypair();

    let (mut client_a, mut server_for_a) = do_handshake(
        &client_a_static,
        &client_a_public,
        &server_static,
        &server_public,
        &[0x61; 32],
    );
    let (mut client_b, mut server_for_b) = do_handshake(
        &client_b_static,
        &client_b_public,
        &server_static,
        &server_public,
        &[0x62; 32],
    );

    let from_a = client_a.encrypt(MsgType::Data, b"client-a").unwrap();
    assert_eq!(server_for_a.decrypt_packet(&from_a).unwrap().1, b"client-a");
    assert!(server_for_b.decrypt_packet(&from_a).is_err());

    let from_b = server_for_b.encrypt(MsgType::Data, b"to-client-b").unwrap();
    assert_eq!(client_b.decrypt_packet(&from_b).unwrap().1, b"to-client-b");
    assert!(client_a.decrypt_packet(&from_b).is_err());

    // A valid client-A initiation cannot be assigned to client B merely by
    // trying another peer entry: the configured static identity must match.
    let init = noise::initiator_start(&client_a_static, &server_public, &[0x61; 32]).unwrap();
    assert!(matches!(
        noise::responder_respond(
            &server_static,
            &client_b_public,
            &[0x62; 32],
            init.handshake_id,
            &init.message,
        ),
        Err(NoiseError::RemoteStaticMismatch) | Err(NoiseError::Snow(_))
    ));
}
