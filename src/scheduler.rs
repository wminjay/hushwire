//! Shared session-maintenance scheduling for platform adapters.
//!
//! The CLI and Network Extension own different packet and socket APIs, but
//! they must make identical decisions about handshake retries, authenticated
//! keepalives, stale-session invalidation, and UDP NAT rebinding.  This module
//! keeps that policy next to the protocol engine while leaving the actual
//! socket rebind and frame delivery to the platform adapter.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::auth;
use crate::config::{Config, TransportConfig};
use crate::engine::{Engine, EngineError, EngineOutput};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduledOperation {
    HandshakeRetry,
    SessionRecovery,
    Keepalive,
}

impl ScheduledOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::HandshakeRetry => "handshake retry",
            Self::SessionRecovery => "session recovery",
            Self::Keepalive => "keepalive",
        }
    }
}

#[derive(Debug)]
pub struct ScheduledOutput {
    pub operation: ScheduledOperation,
    pub output: EngineOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerEvent {
    Recovery {
        peer_name: String,
        silence: Duration,
        rebind_udp: bool,
        rebind_succeeded: bool,
        had_stale_state: bool,
    },
}

#[derive(Debug)]
pub struct SchedulerError {
    pub peer_name: String,
    pub operation: ScheduledOperation,
    pub error: EngineError,
}

#[derive(Debug, Default)]
pub struct SchedulerTick {
    pub outputs: Vec<ScheduledOutput>,
    pub events: Vec<SchedulerEvent>,
    pub errors: Vec<SchedulerError>,
}

#[derive(Clone, Debug)]
struct ScheduledPeer {
    name: String,
    persistent_keepalive: Duration,
    recovery: Option<RecoveryPolicy>,
}

/// Mutable timing state for one running [`Engine`].
///
/// Create a fresh scheduler whenever the engine starts. Reusing one after a
/// stop would carry health timestamps from the erased cryptographic session.
#[derive(Debug)]
pub struct EngineScheduler {
    peers: Vec<ScheduledPeer>,
    last_sent: HashMap<String, Instant>,
    last_udp_rebind_attempt: Option<Instant>,
    last_session_recovery_attempt: HashMap<String, Instant>,
}

impl EngineScheduler {
    pub fn new(config: &Config) -> Self {
        let peers = config
            .peer
            .iter()
            .map(|peer| ScheduledPeer {
                name: peer.name.clone(),
                persistent_keepalive: Duration::from_secs(u64::from(peer.persistent_keepalive)),
                recovery: recovery_policy(
                    config.interface.transport,
                    peer.udp_rebind_after,
                    peer.effective_session_timeout(config.interface.transport),
                ),
            })
            .collect();
        Self {
            peers,
            last_sent: HashMap::new(),
            last_udp_rebind_attempt: None,
            last_session_recovery_attempt: HashMap::new(),
        }
    }

    /// Run one maintenance tick.
    ///
    /// `rebind_udp` must synchronously switch the adapter's shared UDP socket
    /// to a fresh local port and return whether that switch succeeded. The
    /// scheduler invokes it before emitting the replacement handshake so the
    /// handshake leaves through the new NAT mapping.
    pub fn tick(
        &mut self,
        engine: &Engine,
        now: Instant,
        mut rebind_udp: impl FnMut(&str, Duration) -> bool,
    ) -> SchedulerTick {
        let mut tick = SchedulerTick::default();

        // Retry the exact pending msg1 even if the packet that triggered it
        // was the only IP packet sent by the operating system.
        for peer in &self.peers {
            if !engine.has_pending_handshake(&peer.name) {
                continue;
            }
            push_engine_output(
                &mut tick,
                &peer.name,
                ScheduledOperation::HandshakeRetry,
                engine.initiate_handshake(&peer.name, now),
            );
        }

        let snapshot = engine.peer_stats();
        let mut rebound = false;

        // Only one recovery is attempted per tick. A UDP rebind is shared by
        // all peers, while session-only recovery remains independently rate
        // limited per peer.
        for peer in &self.peers {
            let Some(policy) = peer.recovery else {
                continue;
            };
            if !self.last_sent.contains_key(&peer.name) || !engine.has_active_session(&peer.name) {
                continue;
            }
            let Some(last_seen) = snapshot.get(&peer.name).and_then(|stats| stats.last_seen) else {
                continue;
            };
            let last_attempt = if policy.rebind_udp {
                self.last_udp_rebind_attempt
            } else {
                self.last_session_recovery_attempt.get(&peer.name).copied()
            };
            if !recovery_due(now, last_seen, last_attempt, policy.timeout) {
                continue;
            }

            let silence = now.saturating_duration_since(last_seen);
            let rebind_succeeded = if policy.rebind_udp {
                self.last_udp_rebind_attempt = Some(now);
                let succeeded = rebind_udp(&peer.name, silence);
                rebound = succeeded;
                succeeded
            } else {
                self.last_session_recovery_attempt
                    .insert(peer.name.clone(), now);
                false
            };

            let had_stale_state = engine.invalidate_peer(&peer.name);
            push_engine_output(
                &mut tick,
                &peer.name,
                ScheduledOperation::SessionRecovery,
                engine.initiate_handshake(&peer.name, now),
            );
            tick.events.push(SchedulerEvent::Recovery {
                peer_name: peer.name.clone(),
                silence,
                rebind_udp: policy.rebind_udp,
                rebind_succeeded,
                had_stale_state,
            });
            break;
        }

        // After a successful UDP rebind, every active peer gets a one-shot
        // authenticated packet so the remote side learns the fresh source
        // port, including peers with periodic keepalives disabled.
        for peer in &self.peers {
            let recovery_enabled = peer.recovery.is_some();
            let should_send = keepalive_should_send(
                now,
                self.last_sent.get(&peer.name).copied(),
                peer.persistent_keepalive,
                recovery_enabled,
                rebound,
            );
            if !should_send {
                if !peer.persistent_keepalive.is_zero() {
                    self.last_sent.entry(peer.name.clone()).or_insert(now);
                }
                continue;
            }

            let had_active_session = engine.has_active_session(&peer.name);
            let payload = if recovery_enabled {
                auth::KEEPALIVE_PROBE_PAYLOAD
            } else {
                &[]
            };
            push_engine_output(
                &mut tick,
                &peer.name,
                ScheduledOperation::Keepalive,
                engine.create_keepalive(&peer.name, payload, now),
            );

            // Recovery-enabled peers without a session keep retrying instead
            // of delaying the pending handshake by a full keepalive interval.
            if had_active_session || !recovery_enabled {
                self.last_sent.insert(peer.name.clone(), now);
            }
        }

        tick
    }
}

fn push_engine_output(
    tick: &mut SchedulerTick,
    peer_name: &str,
    operation: ScheduledOperation,
    result: Result<EngineOutput, EngineError>,
) {
    match result {
        Ok(output) => tick.outputs.push(ScheduledOutput { operation, output }),
        Err(error) => tick.errors.push(SchedulerError {
            peer_name: peer_name.to_string(),
            operation,
            error,
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryPolicy {
    timeout: Duration,
    rebind_udp: bool,
}

fn recovery_policy(
    transport: TransportConfig,
    udp_rebind_after: u16,
    session_timeout: u64,
) -> Option<RecoveryPolicy> {
    if transport == TransportConfig::Udp && udp_rebind_after > 0 {
        return Some(RecoveryPolicy {
            timeout: Duration::from_secs(u64::from(udp_rebind_after)),
            rebind_udp: true,
        });
    }
    (session_timeout > 0).then_some(RecoveryPolicy {
        timeout: Duration::from_secs(session_timeout),
        rebind_udp: false,
    })
}

fn recovery_due(
    now: Instant,
    last_seen: Instant,
    last_recovery_attempt: Option<Instant>,
    timeout: Duration,
) -> bool {
    let health_baseline = last_recovery_attempt
        .map(|attempt| attempt.max(last_seen))
        .unwrap_or(last_seen);
    now.saturating_duration_since(health_baseline) >= timeout
}

fn keepalive_should_send(
    now: Instant,
    last_sent: Option<Instant>,
    interval: Duration,
    recovery_enabled: bool,
    rebound: bool,
) -> bool {
    if rebound {
        return true;
    }
    if interval.is_zero() {
        return false;
    }
    last_sent
        .map(|sent| now.saturating_duration_since(sent) >= interval)
        .unwrap_or(recovery_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_rebind_policy_takes_precedence_over_session_timeout() {
        assert_eq!(
            recovery_policy(TransportConfig::Udp, 90, 30),
            Some(RecoveryPolicy {
                timeout: Duration::from_secs(90),
                rebind_udp: true,
            })
        );
    }

    #[test]
    fn tcp_uses_session_only_recovery() {
        assert_eq!(
            recovery_policy(TransportConfig::Tcp, 0, 15),
            Some(RecoveryPolicy {
                timeout: Duration::from_secs(15),
                rebind_udp: false,
            })
        );
    }

    #[test]
    fn recovery_attempts_are_rate_limited_against_latest_health_signal() {
        let now = Instant::now();
        let stale = now.checked_sub(Duration::from_secs(180)).unwrap();
        assert!(recovery_due(now, stale, None, Duration::from_secs(90)));

        let recent_attempt = now.checked_sub(Duration::from_secs(5));
        assert!(!recovery_due(
            now,
            stale,
            recent_attempt,
            Duration::from_secs(90)
        ));

        let recent_packet = now.checked_sub(Duration::from_secs(5)).unwrap();
        let old_attempt = now.checked_sub(Duration::from_secs(120));
        assert!(!recovery_due(
            now,
            recent_packet,
            old_attempt,
            Duration::from_secs(90)
        ));
    }

    #[test]
    fn rebind_forces_one_shot_keepalive_even_when_periodic_interval_is_zero() {
        assert!(keepalive_should_send(
            Instant::now(),
            None,
            Duration::ZERO,
            false,
            true
        ));
    }

    #[test]
    fn peer_without_keepalive_stays_silent_without_rebind() {
        assert!(!keepalive_should_send(
            Instant::now(),
            None,
            Duration::ZERO,
            false,
            false
        ));
    }
}
