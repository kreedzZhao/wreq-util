//! Offline check: send one request with Emulation::Chrome152 at a local server and
//! print the headers it received, to diff against a capture from real Chromium 152.
use wreq::Client;
use wreq_util::Emulation;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).expect("usage: verify_chrome152 <url>");
    let client = Client::builder().emulation(Emulation::Chrome152).build()?;
    let resp = client.get(&url).send().await?;
    println!("status: {}", resp.status());
    Ok(())
}
