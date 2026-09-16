use argon2::{Algorithm, Argon2, Params, Version};

use crate::{error::CryptoError, secret::SecretKey};

pub const SALT_LEN: usize = 16;

pub const MIN_M_COST_KIB: u32 = 64 * 1024;

pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;

pub const MIN_T_COST: u32 = 2;

pub const MAX_T_COST: u32 = 16;

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
        if self.m_cost_kib < 8 * self.p_cost {
            return Err(CryptoError::KdfParams("memory cost too low for lanes"));
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
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    if elapsed_ms <= 0.0 {
        return KdfParams::default();
    }

    let t_cost = 3u32;
    let scale = (f64::from(target_ms) / elapsed_ms) * (f64::from(MIN_T_COST) / f64::from(t_cost));
    let scaled = f64::from(MIN_M_COST_KIB) * scale;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let m_cost_kib =
        (scaled.clamp(f64::from(MIN_M_COST_KIB), f64::from(MAX_M_COST_KIB)) as u32 / 1024) * 1024;

    KdfParams {
        m_cost_kib: m_cost_kib.max(MIN_M_COST_KIB),
        t_cost,
        p_cost: lanes,
    }
}
