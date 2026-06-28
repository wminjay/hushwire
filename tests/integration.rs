//! Integration tests: simulate two nodes doing a Noise handshake in memory,
//! then exchanging data packets with the derived session keys.
//!
//! These tests verify the core crypto pipeline end-to-end:
//!   handshake → session key derivation → data encrypt/decrypt → replay rejection
//!
//! No TUN devices, UDP sockets, or threads are involved — the tests exercise
//! the noise + auth modules directly, simulating what tunnel.rs does at runtime.

use hushwire::auth::{self, MsgType};
use hushwire::noise;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a random static key pair (like `hushwire genkey`).
fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Simulate a full Noise_IKpsk2 handshake between initiator and responder.
/// Returns both sessions if successful.
fn do_handshake(
    i_static: &StaticSecret,
    r_static: &StaticSecret,
    r_pub: &PublicKey,
    psk: &[u8; 32],
) -> (noise::Session, noise::Session) {
    // Initiator starts.
    let init = noise::initiator_start(i_static, r_pub, psk);
    let (msg1, state) = init.into_parts();

    // Responder responds.
    let resp =
        noise::responder_respond(r_static, psk, &msg1).expect("responder should accept msg1");

    // Initiator finalizes.
    let i_session = noise::initiator_finalize(state, i_static, r_pub, &resp.message)
        .expect("initiator should accept msg2");

    (i_session, resp.session)
}

#[test]
fn full_handshake_then_data_round_trip() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    let (i_session, r_session) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // Verify keys match (initiator send = responder recv, vice versa).
    assert_eq!(i_session.send_key, r_session.recv_key);
    assert_eq!(i_session.recv_key, r_session.send_key);
    assert_eq!(i_session.session_id, r_session.session_id);

    // Initiator encrypts a data packet.
    let payload = b"hello from initiator";
    let packet = auth::encode_packet(
        payload,
        &i_session.send_key,
        MsgType::Data,
        &i_session.session_id,
    );

    // Responder decrypts it.
    let (msg_type, decoded) = auth::decode_packet(&packet, &r_session.recv_key)
        .expect("responder should decrypt initiator's packet");
    assert_eq!(msg_type, MsgType::Data);
    assert_eq!(&decoded, payload);

    // Responder encrypts a reply.
    let reply = b"hello from responder";
    let reply_packet = auth::encode_packet(
        reply,
        &r_session.send_key,
        MsgType::Data,
        &r_session.session_id,
    );

    // Initiator decrypts the reply.
    let (msg_type2, decoded2) = auth::decode_packet(&reply_packet, &i_session.recv_key)
        .expect("initiator should decrypt responder's reply");
    assert_eq!(msg_type2, MsgType::Data);
    assert_eq!(&decoded2, reply);
}

#[test]
fn keepalive_round_trip_after_handshake() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    let (i_session, r_session) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // Initiator sends a keepalive (empty payload).
    let keepalive = auth::encode_packet(
        b"",
        &i_session.send_key,
        MsgType::Keepalive,
        &i_session.session_id,
    );

    // Responder decrypts it.
    let (msg_type, decoded) = auth::decode_packet(&keepalive, &r_session.recv_key)
        .expect("responder should decrypt keepalive");
    assert_eq!(msg_type, MsgType::Keepalive);
    assert!(decoded.is_empty());
}

#[test]
fn wrong_session_key_cannot_decrypt() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    let (i_session, _r_session) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // A completely different key pair does a handshake.
    let (i2_static, _) = gen_keypair();
    let (r2_static, r2_pub) = gen_keypair();
    let (i2_session, _r2_session) = do_handshake(&i2_static, &r2_static, &r2_pub, &psk);

    // Packet from session 1 cannot be decrypted with session 2's key.
    let packet = auth::encode_packet(
        b"secret",
        &i_session.send_key,
        MsgType::Data,
        &i_session.session_id,
    );
    assert!(auth::decode_packet(&packet, &i2_session.recv_key).is_none());
}

#[test]
fn replayed_packet_rejected_by_filter() {
    use hushwire::replay::ReplayFilter;

    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    let (i_session, r_session) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // Initiator sends a data packet.
    let packet = auth::encode_packet(
        b"data",
        &i_session.send_key,
        MsgType::Data,
        &i_session.session_id,
    );

    // Extract the nonce (session_id + nonce_rand) for replay filtering.
    let mut nonce = [0u8; auth::NONCE_SIZE];
    nonce.copy_from_slice(&packet[auth::SESSION_ID_OFFSET..auth::HEADER_SIZE]);

    // Responder sets up a replay filter.
    let mut filter = ReplayFilter::new();

    // First time: accepted.
    assert!(
        filter.check_and_insert(&nonce),
        "first packet should be accepted"
    );

    // Decrypt succeeds.
    assert!(auth::decode_packet(&packet, &r_session.recv_key).is_some());

    // Second time (replay): rejected by filter.
    assert!(
        !filter.check_and_insert(&nonce),
        "replayed packet should be rejected"
    );
}

#[test]
fn session_id_in_packet_matches_session() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    let (i_session, _r_session) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    let packet = auth::encode_packet(
        b"data",
        &i_session.send_key,
        MsgType::Data,
        &i_session.session_id,
    );

    // Extract session_id from packet — should match the session's.
    let extracted = auth::extract_session_id(&packet).expect("should extract session_id");
    assert_eq!(extracted, i_session.session_id);
}

#[test]
fn handshake_with_wrong_psk_produces_different_keys() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();

    let (i_s1, _r_s1) = do_handshake(&i_static, &r_static, &r_pub, &[0x42u8; 32]);

    // The responder with wrong PSK can't even decrypt msg1 (static_i is encrypted
    // under PSK). So the handshake fails entirely.
    let init = noise::initiator_start(&i_static, &r_pub, &[0x42u8; 32]);
    let (msg1, _) = init.into_parts();
    assert!(noise::responder_respond(&r_static, &[0xabu8; 32], &msg1).is_none());

    // But if both sides use the same wrong PSK, handshake succeeds but keys differ.
    let (i_s2, r_s2) = do_handshake(&i_static, &r_static, &r_pub, &[0xabu8; 32]);

    assert_ne!(
        i_s1.send_key, i_s2.send_key,
        "different PSK should produce different keys"
    );
    assert_eq!(
        i_s2.send_key, r_s2.recv_key,
        "but both sides still match each other"
    );
}

#[test]
fn handshake_init_message_has_correct_type() {
    let (i_static, _) = gen_keypair();
    let (_, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    // The handshake messages, when wrapped in auth packets, should have
    // the correct msg_type so the receiver can distinguish them from data.
    let init = noise::initiator_start(&i_static, &r_pub, &psk);
    let (msg1, _) = init.into_parts();

    let hs_packet = auth::encode_packet(&msg1, &psk, MsgType::HandshakeInit, &[0u8; 8]);
    let (msg_type, _) = auth::decode_packet(&hs_packet, &psk).expect("should decrypt");
    assert_eq!(msg_type, MsgType::HandshakeInit);
    assert!(msg_type.is_handshake());
}

#[test]
fn multiple_handshake_cycles_produce_fresh_keys() {
    let (i_static, _) = gen_keypair();
    let (r_static, r_pub) = gen_keypair();
    let psk = [0x42u8; 32];

    // First handshake.
    let (i_s1, _r_s1) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // Second handshake (rekey).
    let (i_s2, r_s2) = do_handshake(&i_static, &r_static, &r_pub, &psk);

    // Session IDs should be different (fresh ephemeral keys each time).
    assert_ne!(i_s1.session_id, i_s2.session_id);

    // Session keys should be different.
    assert_ne!(i_s1.send_key, i_s2.send_key);

    // But each pair still matches.
    assert_eq!(i_s2.send_key, r_s2.recv_key);
}
