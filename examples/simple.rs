use github_device_oauth::*;

#[tokio::main]
async fn main() {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
    let refresh_token = std::env::var("GITHUB_REFRESH_TOKEN").ok();
    let host = "github.com".to_owned();
    let scopes = "read:user".to_owned();
    let flow = DeviceFlow::new(client_id, host, scopes);
    let cred = flow.refresh_or_authorize(refresh_token).await.unwrap();
    dbg!(cred);
}
