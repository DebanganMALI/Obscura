use argon2::{Algorithm, Argon2, Params, Version};

use crate::{error::CryptoError, secret::SecretKey};

pub const SALT_LEN: usize = 16;

pub const MIN_M_COST_KIB: u32 = 64 * 1024;

pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;

pub const MIN_T_COST: u32 = 2;

pub const MAX_T_COST: u32 = 16;

const _: () = assert!(MIN_M_COST_KIB >= 8 * 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    pub const fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost_kib < MIN_M_COST_KIB {
            return Err(CryptoError::KdfParams("memory cost below 64 MiB"));
        }
        if self.m_cost_kib > MAX_M_COST_KIB {
            return Err(CryptoError::KdfParams("memory cost above 2 GiB"));
        }
        if self.t_cost < MIN_T_COST {
            return Err(CryptoError::KdfParams("time cost below 2 passes"));
        }
        if self.t_cost > MAX_T_COST {
            return Err(CryptoError::KdfParams("time cost above 16 passes"));
        }
        if self.p_cost == 0 || self.p_cost > 64 {
            return Err(CryptoError::KdfParams("parallelism outside 1..=64"));
        }
        Ok(())
    }
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    params.validate()?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(crate::secret::KEY_LEN),
    )
    .map_err(|_| CryptoError::KdfParams("rejected by Argon2"))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = SecretKey::zeroed();
    argon
        .hash_password_into(password, salt, out.expose_mut())
        .map_err(|_| CryptoError::KdfFailed)?;

    Ok(out)
}

pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    use rand_core::{OsRng, TryRngCore};
    let mut salt = [0u8; SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::Rng)?;
    Ok(salt)
}

#[cfg(feature = "calibrate")]
const CALIBRATED_T_COST: u32 = 3;

#[cfg(feature = "calibrate")]
fn millis(elapsed: std::time::Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

#[cfg(feature = "calibrate")]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn scale_m_cost(target_ms: u32, elapsed_ms: f64, probe_t_cost: u32, t_cost: u32) -> Option<u32> {
    if !elapsed_ms.is_finite() || elapsed_ms <= 0.0 || t_cost == 0 {
        return None;
    }

    let scale = (f64::from(target_ms) / elapsed_ms) * (f64::from(probe_t_cost) / f64::from(t_cost));
    let scaled = f64::from(MIN_M_COST_KIB) * scale;
    let clamped = scaled.clamp(f64::from(MIN_M_COST_KIB), f64::from(MAX_M_COST_KIB));

    Some(((clamped as u32 / 1024) * 1024).max(MIN_M_COST_KIB))
}

#[cfg(feature = "calibrate")]
#[must_use]
pub fn calibrate(target_ms: u32) -> KdfParams {
    use std::time::Instant;

    let lanes = std::thread::available_parallelism()
        .map_or(4, |n| u32::try_from(n.get()).unwrap_or(4))
        .clamp(1, 8);

    let probe = KdfParams {
        m_cost_kib: MIN_M_COST_KIB,
        t_cost: MIN_T_COST,
        p_cost: lanes,
    };

    let salt = [0u8; SALT_LEN];
    let start = Instant::now();
    if derive_key(b"obscura-calibration-probe", &salt, probe).is_err() {
        return KdfParams::default();
    }

    match scale_m_cost(
        target_ms,
        millis(start.elapsed()),
        MIN_T_COST,
        CALIBRATED_T_COST,
    ) {
        Some(m_cost_kib) => KdfParams {
            m_cost_kib,
            t_cost: CALIBRATED_T_COST,
            p_cost: lanes,
        },
        None => KdfParams::default(),
    }
}

#[cfg(all(test, feature = "calibrate"))]
mod calibration {
    use super::*;

    #[test]
    fn a_duration_becomes_the_milliseconds_it_represents() {
        assert!((millis(std::time::Duration::from_millis(250)) - 250.0).abs() < 1e-9);
        assert!((millis(std::time::Duration::from_secs(2)) - 2000.0).abs() < 1e-9);
    }

    #[test]
    fn a_probe_that_took_no_time_leaves_nothing_to_scale_from() {
        assert_eq!(scale_m_cost(250, 0.0, MIN_T_COST, CALIBRATED_T_COST), None);
        assert_eq!(scale_m_cost(250, -1.0, MIN_T_COST, CALIBRATED_T_COST), None);
        assert_eq!(
            scale_m_cost(250, f64::NAN, MIN_T_COST, CALIBRATED_T_COST),
            None
        );
        assert_eq!(scale_m_cost(250, 50.0, MIN_T_COST, 0), None);
        assert!(scale_m_cost(250, 50.0, MIN_T_COST, CALIBRATED_T_COST).is_some());
    }

    #[test]
    fn the_scaled_memory_cost_is_stable() {
        assert_eq!(
            scale_m_cost(250, 50.0, MIN_T_COST, CALIBRATED_T_COST),
            Some(218_112)
        );
    }

    #[test]
    fn the_scaled_memory_cost_stays_inside_the_accepted_range() {
        assert_eq!(
            scale_m_cost(0, 50.0, MIN_T_COST, CALIBRATED_T_COST),
            Some(MIN_M_COST_KIB)
        );
        assert_eq!(
            scale_m_cost(u32::MAX, 1.0, MIN_T_COST, CALIBRATED_T_COST),
            Some(MAX_M_COST_KIB)
        );
    }

    #[test]
    fn a_slower_machine_is_given_less_work() {
        let fast = scale_m_cost(500, 20.0, MIN_T_COST, CALIBRATED_T_COST);
        let slow = scale_m_cost(500, 200.0, MIN_T_COST, CALIBRATED_T_COST);
        assert!(fast > slow);
    }

    #[test]
    fn calibration_answers_the_target_it_was_given() {
        assert_ne!(calibrate(0).m_cost_kib, calibrate(60_000).m_cost_kib);
    }
}

#[cfg(test)]
mod parameter_bounds {
    use super::*;

    fn params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> KdfParams {
        KdfParams {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    #[test]
    fn the_memory_bounds_are_accepted_at_their_edges_and_not_past_them() {
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 1).validate().is_ok());
        assert!(params(MIN_M_COST_KIB - 1, MIN_T_COST, 1)
            .validate()
            .is_err());
        assert!(params(MAX_M_COST_KIB, MIN_T_COST, 1).validate().is_ok());
        assert!(params(MAX_M_COST_KIB + 1, MIN_T_COST, 1)
            .validate()
            .is_err());
    }

    #[test]
    fn the_time_bounds_are_accepted_at_their_edges_and_not_past_them() {
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 1).validate().is_ok());
        assert!(params(MIN_M_COST_KIB, MIN_T_COST - 1, 1)
            .validate()
            .is_err());
        assert!(params(MIN_M_COST_KIB, MAX_T_COST, 1).validate().is_ok());
        assert!(params(MIN_M_COST_KIB, MAX_T_COST + 1, 1)
            .validate()
            .is_err());
    }

    #[test]
    fn the_lane_bounds_are_accepted_at_their_edges_and_not_past_them() {
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 1).validate().is_ok());
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 0).validate().is_err());
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 64).validate().is_ok());
        assert!(params(MIN_M_COST_KIB, MIN_T_COST, 65).validate().is_err());
    }
}
