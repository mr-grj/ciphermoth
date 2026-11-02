use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

const SECRET_BYTES: usize = 32;
const MAX_MATERIAL_BYTES: usize = 2048;

#[derive(Serialize)]
pub struct Enrolled {
    credential_id: String,
    material: String,
    secret: String,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn cm_biometric_available() -> i32;
    fn cm_biometric_enroll(
        material: *mut u8,
        capacity: usize,
        length: *mut usize,
        secret: *mut u8,
    ) -> i32;
    fn cm_biometric_derive(material: *const u8, length: usize, secret: *mut u8) -> i32;
}

#[cfg(target_os = "macos")]
fn outcome(code: i32) -> Result<(), String> {
    match code {
        0 => Ok(()),
        1 => Err("cancelled".into()),
        2 => Err("invalid".into()),
        3 => Err("unavailable".into()),
        _ => Err("failed".into()),
    }
}

// Each runs on a blocking thread: the system sheet waits for the fingerprint.
#[cfg(target_os = "macos")]
fn enroll_now() -> Result<(Vec<u8>, [u8; SECRET_BYTES]), String> {
    let mut material = vec![0u8; MAX_MATERIAL_BYTES];
    let mut length = 0usize;
    let mut secret = [0u8; SECRET_BYTES];
    outcome(unsafe {
        cm_biometric_enroll(
            material.as_mut_ptr(),
            material.len(),
            &mut length,
            secret.as_mut_ptr(),
        )
    })?;
    material.truncate(length);
    Ok((material, secret))
}

#[cfg(target_os = "macos")]
fn derive_now(material: &[u8]) -> Result<[u8; SECRET_BYTES], String> {
    let mut secret = [0u8; SECRET_BYTES];
    outcome(unsafe {
        cm_biometric_derive(material.as_ptr(), material.len(), secret.as_mut_ptr())
    })?;
    Ok(secret)
}

#[cfg(not(target_os = "macos"))]
fn enroll_now() -> Result<(Vec<u8>, [u8; SECRET_BYTES]), String> {
    Err("unavailable".into())
}

#[cfg(not(target_os = "macos"))]
fn derive_now(_material: &[u8]) -> Result<[u8; SECRET_BYTES], String> {
    Err("unavailable".into())
}

#[tauri::command]
pub fn biometric_available() -> bool {
    #[cfg(target_os = "macos")]
    return unsafe { cm_biometric_available() } == 1;
    #[cfg(not(target_os = "macos"))]
    return false;
}

#[tauri::command]
pub async fn biometric_enroll() -> Result<Enrolled, String> {
    let (material, secret) = tauri::async_runtime::spawn_blocking(enroll_now)
        .await
        .map_err(|_| "failed".to_string())??;
    Ok(Enrolled {
        credential_id: uuid::Uuid::new_v4().simple().to_string(),
        material: URL_SAFE_NO_PAD.encode(material),
        secret: URL_SAFE_NO_PAD.encode(secret),
    })
}

#[tauri::command]
pub async fn biometric_derive(material: String) -> Result<String, String> {
    if material.len() > MAX_MATERIAL_BYTES * 2 {
        return Err("invalid".into());
    }
    let material = URL_SAFE_NO_PAD
        .decode(material)
        .map_err(|_| "invalid".to_string())?;
    let secret = tauri::async_runtime::spawn_blocking(move || derive_now(&material))
        .await
        .map_err(|_| "failed".to_string())??;
    Ok(URL_SAFE_NO_PAD.encode(secret))
}
