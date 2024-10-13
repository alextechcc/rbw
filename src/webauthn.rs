use anyhow::Context;
use reqwest::Url;
use tokio_stream::StreamExt;
use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator, transport::{AnyTransport, TokenEvent, Transport}, types::{CableRequestType, CableState, EnrollSampleStatus}, ui::UiCallback, AuthenticatorBackend
};
use webauthn_rs_proto::PublicKeyCredentialRequestOptions;

use crate::locked::Password;

pub async fn webauthn(
    challenge: PublicKeyCredentialRequestOptions,
    pin: &str,
) -> Result<Password, Box<dyn std::error::Error + Send + Sync>> {
    let mut trans = AnyTransport::new()
        .await
        .ok()
        .ok_or("Failed to set up webauthn transport")?;

    let ui = Pinentry {
        pin: pin.to_string(),
    };
    let mut stream = trans
        .watch()
        .await
        .ok()
        .ok_or("Failed to get transport stream")?;

    let mut authenticator = None;

    while let Some(event) = stream.next().await {
        eprintln!("Got stream event {:?}", event);
        match event {
            TokenEvent::Added(t) => {
                match CtapAuthenticator::new(t, &ui).await {
                    Some(a) => {
                        authenticator = Some(a);
                    },
                    None => continue,
                };
            },
            TokenEvent::EnumerationComplete => {
                break;
            },
            _ => continue,
        }
    }

    let mut authi = authenticator.ok_or("No authenticator found")?;

    let origin = crate::config::Config::load_async()
        .await
        .ok()
        .ok_or("error loading config")?
        .base_url
        .ok_or("error loading base_url")?;

    let origin = Url::parse(&origin).context("Failed to parse origin")?;

    let result = authi.perform_auth(origin, challenge, 60000);
    // required, so that the JSON is parsed corretly by the server
    let out = serde_json::to_string(&result.unwrap())?
        .replace("\"appid\":null,\"hmac_get_secret\":null", "\"appid\":false")
        .replace("clientDataJSON", "clientDataJson");

    let mut buf = crate::locked::Vec::new();
    buf.extend(out.as_bytes().iter().copied());
    Ok(Password::new(buf))
}

#[derive(Debug)]
struct Pinentry {
    pin: String,
}

impl UiCallback for Pinentry {
    fn request_pin(&self) -> Option<String> {
        return Some(self.pin.clone());
    }

    fn request_touch(&self) {
        println!("Called unimplemented method: request_touch")
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        println!(
            "Called unimplemented method: fingerprint_enrollment_feedback"
        )
    }

    fn processing(&self) {
        println!("Called unimplemented method: processing");
    }

    fn cable_qr_code(&self, request_type: CableRequestType, url: String) {
        println!("Called unimplemented method: cable_qr_code")
    }

    fn dismiss_qr_code(&self) {
        println!("Called unimplemented method: dismiss_qr_code")
    }

    fn cable_status_update(&self, state: CableState) {
        println!("Called unimplemented method: cable_status_update")
    }
}
