use std::ffi::c_int;
use std::os::raw::c_long;
use std::sync::{Arc, OnceLock, RwLock};

use foreign_types_shared::ForeignTypeRef;
use openssl::sha::sha256;
use openssl::ssl::SslContextRef;
use openssl_sys::{
    EVP_DecryptInit_ex, EVP_EncryptInit_ex, EVP_MAC_init, EVP_aes_256_cbc, RAND_bytes,
    EVP_CIPHER_CTX, EVP_MAC_CTX, SSL, SSL_CTX,
};

use crate::Error;

const KEY_LEN: usize = 32;
const NAME_LEN: usize = 16;
const CIPHER_LEN: usize = 32;
const HMAC_LEN: usize = 32;
const IV_LEN: usize = 16;

struct TicketKey {
    name: [u8; NAME_LEN],
    cipher: [u8; CIPHER_LEN],
    hmac: [u8; HMAC_LEN],
}

static TICKET_KEY: OnceLock<RwLock<Option<Arc<TicketKey>>>> = OnceLock::new();

type TicketCallback = unsafe extern "C" fn(
    *mut SSL,
    *mut u8,
    *mut u8,
    *mut EVP_CIPHER_CTX,
    *mut EVP_MAC_CTX,
    c_int,
) -> c_int;

unsafe extern "C" {
    fn SSL_CTX_set_tlsext_ticket_key_evp_cb(
        ctx: *mut SSL_CTX,
        callback: Option<TicketCallback>,
    ) -> c_long;
}

pub(crate) fn install(context: &SslContextRef, key: &[u8]) -> Result<(), Error> {
    let key = derive(key)?;
    let lock = TICKET_KEY.get_or_init(|| RwLock::new(None));
    *lock
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(key));

    let result = unsafe { SSL_CTX_set_tlsext_ticket_key_evp_cb(context.as_ptr(), Some(callback)) };
    if result != 1 {
        return Err(Error::TicketKey(
            "OpenSSL rejected the ticket key callback".to_owned(),
        ));
    }
    Ok(())
}

fn derive(key: &[u8]) -> Result<TicketKey, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::TicketKey(format!(
            "expected {KEY_LEN} bytes, got {}",
            key.len()
        )));
    }

    let mut seed = Vec::with_capacity(KEY_LEN + 1);
    seed.extend_from_slice(key);
    let mut hash = |index: u8| {
        seed.truncate(KEY_LEN);
        seed.push(index);
        sha256(&seed)
    };
    let name_hash = hash(0);
    let cipher = hash(1);
    let hmac = hash(2);

    let mut name = [0u8; NAME_LEN];
    name.copy_from_slice(&name_hash[..NAME_LEN]);
    Ok(TicketKey { name, cipher, hmac })
}

unsafe extern "C" fn callback(
    _ssl: *mut SSL,
    name: *mut u8,
    iv: *mut u8,
    cipher_context: *mut EVP_CIPHER_CTX,
    hmac_context: *mut EVP_MAC_CTX,
    encrypt: c_int,
) -> c_int {
    let lock = match TICKET_KEY.get() {
        Some(lock) => lock,
        None => return 0,
    };
    let guard = match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(key) = guard.as_ref() else {
        return 0;
    };

    if encrypt == 1 {
        std::ptr::copy_nonoverlapping(key.name.as_ptr(), name, NAME_LEN);
        if RAND_bytes(iv, IV_LEN as c_int) != 1 {
            return 0;
        }
        if EVP_EncryptInit_ex(
            cipher_context,
            EVP_aes_256_cbc(),
            std::ptr::null_mut(),
            key.cipher.as_ptr(),
            iv,
        ) != 1
        {
            return 0;
        }
    } else {
        let ticket_name = std::slice::from_raw_parts(name, NAME_LEN);
        if ticket_name != key.name {
            return 0;
        }
        if EVP_DecryptInit_ex(
            cipher_context,
            EVP_aes_256_cbc(),
            std::ptr::null_mut(),
            key.cipher.as_ptr(),
            iv,
        ) != 1
        {
            return 0;
        }
    }

    if EVP_MAC_init(hmac_context, key.hmac.as_ptr(), HMAC_LEN, std::ptr::null()) != 1 {
        return 0;
    }
    1
}
