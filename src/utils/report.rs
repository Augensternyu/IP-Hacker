use regex::Regex;
use reqwest::Client;
use std::time::Duration;

pub async fn get_usage_count() -> Result<(u64, u64), String> {
    let client = Client::new();
    let text = match client.get("https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Frsbench%2Frsbench&label=&icon=github&color=%23160d27")
        .timeout(Duration::from_secs(1)).send().await {
        Ok(res) => {
            match res.text().await {
                Ok(text) => text,
                Err(_) => {
                    return Err("Can not parse response".to_string())
                }
            }
        }
        Err(_) => {
            return Err("Can not parse response".to_string())
        }
    };

    let re = Regex::new(r"\d+\s/\s\d+").unwrap();
    let line = if let Some(text) = re.find(&text) {
        text.as_str()
    } else {
        return Err("Can not parse response".to_string());
    };

    let vec = line.split('/').collect::<Vec<&str>>();

    Ok((
        vec[0].trim().parse::<u64>().unwrap(),
        vec[1].trim().parse::<u64>().unwrap(),
    ))
}
