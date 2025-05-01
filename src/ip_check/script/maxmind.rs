use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::NoError;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::header;
use std::net::IpAddr;
use std::str::FromStr;

pub struct Maxmind;

#[async_trait]
impl IpCheck for Maxmind {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let mut ip_results = Vec::new();
            ip_results.push(get_maxmind_info(ip).await);
            ip_results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return create_reqwest_client_error("Maxmind");
                };

                let Ok(result) = client_v4.get("https://4.ipcheck.ing/").send().await else {
                    return request_error_ip_result(
                        "Maxmind",
                        "Unable to connect to ipcheck.ing",
                    );
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("Maxmind", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("Maxmind", text);
                };
                get_maxmind_info(ip).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
                else {
                    return create_reqwest_client_error("Maxmind");
                };

                let Ok(result) = client_v4.get("https://6.ipcheck.ing/").send().await else {
                    return request_error_ip_result(
                        "Maxmind",
                        "Unable to connect to ipcheck.ing",
                    );
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("Maxmind", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("Maxmind", text);
                };
                get_maxmind_info(ip).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            if let Ok(result) = handle_v6.await {
                results.push(result);
            }
            results
        }
    }
}

async fn get_maxmind_info(ip: IpAddr) -> IpResult {
    let Ok(client) = create_reqwest_client(None, None).await else {
        return create_reqwest_client_error("Maxmind");
    };

    let mut headers = header::HeaderMap::new();
    headers.insert("referer", "https://ipcheck.ing/".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let Ok(res) = client
        .get(format!(
            "https://ipcheck.ing/api/maxmind?ip={ip}&lang=en"
        ))
        .headers(headers)
        .send()
        .await
    else {
        return request_error_ip_result("Maxmind", "Unable to connect to ipcheck.ing");
    };

    let Ok(json) = res.json::<serde_json::Value>().await else {
        return json_parse_error_ip_result(
            "Maxmind",
            "Unable to parse the returned result into Json",
        );
    };

    let country = if let Some(country) = json.get("country_name") {
        if let Some(country) = country.as_str() {
            country.to_string()
        } else {
            return json_parse_error_ip_result("Maxmind", "Unable to get value for `country`");
        }
    } else {
        return json_parse_error_ip_result("Maxmind", "Unable to get value for `country`");
    };

    let region = if let Some(region) = json.get("region") {
        if let Some(region) = region.as_str() {
            region.to_string()
        } else {
            return json_parse_error_ip_result("Maxmind", "Unable to get value for `region`");
        }
    } else {
        return json_parse_error_ip_result("Maxmind", "Unable to get value for `region`");
    };

    let city = if let Some(city) = json.get("city") {
        if let Some(city) = city.as_str() {
            city.to_string()
        } else {
            return json_parse_error_ip_result("Maxmind", "Unable to get value for `city`");
        }
    } else {
        return json_parse_error_ip_result("Maxmind", "Unable to get value for `city`");
    };

    let asn = if let Some(asn) = json.get("asn") {
        if let Some(asn) = asn.as_str() {
            asn.to_string()
                .replace("AS", "")
                .parse::<u32>()
                .unwrap_or(0)
        } else {
            return json_parse_error_ip_result("Maxmind", "Unable to get value for `asn`");
        }
    } else {
        return json_parse_error_ip_result("Maxmind", "Unable to get value for `asn`");
    };

    let org = if let Some(org) = json.get("org") {
        if let Some(org) = org.as_str() {
            org.to_string()
        } else {
            return json_parse_error_ip_result("Maxmind", "Unable to get value for `org`");
        }
    } else {
        return json_parse_error_ip_result("Maxmind", "Unable to get value for `org`");
    };

    let lat = if let Some(lat) = json.get("latitude") {
        if let Some(lat) = lat.as_f64() {
            Some(lat.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let lon = if let Some(lng) = json.get("longitude") {
        if let Some(lng) = lng.as_f64() {
            Some(lng.to_string())
        } else {
            None
        }
    } else {
        None
    };

    IpResult {
        success: true,
        error: NoError,
        provider: "Maxmind".to_string(),
        ip: Some(ip),
        autonomous_system: Some(AS {
            number: asn,
            name: org,
        }),
        region: Some(Region {
            country: Some(country),
            region: Some(region),
            city: Some(city),
            coordinates: if let (Some(lat), Some(lon)) = (lat, lon) {
                Some(Coordinates { lat, lon })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: None,
    }
}
