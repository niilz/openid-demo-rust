use openid::request::create_request;

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let res = reqwest::get("http://google.de").await?.text().await?;
    println!("{:?}", res);
    println!("{}", create_request());
    Ok(())
}
