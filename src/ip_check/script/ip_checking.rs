use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::{AS, Coordinates, IpResult, Region, Risk, RiskTag};
use crate::ip_check::script::{create_reqwest_client, failed_ip_result};
use async_trait::async_trait;
use log::{debug, trace};
use reqwest::{Client, header};
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpChecking;

#[async_trait]
impl IpCheck for IpChecking {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let mut ip_results = Vec::new();
            ip_results.push(get_ipcheck_ing_info(ip).await);
            ip_results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return failed_ip_result("IpCheck.ing");
                };

                let Ok(result) = client_v4.get("https://4.ipcheck.ing/").send().await else {
                    return failed_ip_result("IpCheck.ing");
                };

                let Ok(text) = result.text().await else {
                    return failed_ip_result("IpCheck.ing");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(&text) else {
                    return failed_ip_result("IpCheck.ing");
                };
                get_ipcheck_ing_info(ip).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
                else {
                    return failed_ip_result("IpCheck.ing");
                };

                let Ok(result) = client_v4.get("https://6.ipcheck.ing/").send().await else {
                    return failed_ip_result("IpCheck.ing");
                };

                let Ok(text) = result.text().await else {
                    return failed_ip_result("IpCheck.ing");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(&text) else {
                    return failed_ip_result("IpCheck.ing");
                };
                get_ipcheck_ing_info(ip).await
            });

            let mut results = Vec::new();
            if let Ok(result) =  handle_v4.await {
                results.push(result);
            }
            if let Ok(result) = handle_v6.await {
                results.push(result);
            }
            results
        }
    }
}

async fn get_ipcheck_ing_info(ip: IpAddr) -> IpResult {
    let Ok(client) = create_reqwest_client(None, None).await else {
        return failed_ip_result("IpCheck.ing");
    };

    let mut headers = header::HeaderMap::new();
    headers.insert("referer", "https://ipcheck.ing/".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let Ok(res) = client
        .get(format!(
            "https://ipcheck.ing/api/ipchecking?ip={ip}&lang=en"
        ))
        .headers(headers)
        .send()
        .await
    else {
        return failed_ip_result("IpCheck.ing");
    };

    let Ok(json) = res.json::<serde_json::Value>().await else {
        return failed_ip_result("IpCheck.ing");
    };

    let country = if let Some(country) = json.get("country_name") {
        if let Some(country) = country.as_str() {
            country.to_string()
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let region = if let Some(region) = json.get("region") {
        if let Some(region) = region.as_str() {
            region.to_string()
        }else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let city = if let Some(city) = json.get("city") {
        if let Some(city) = city.as_str() {
            city.to_string()
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let asn = if let Some(asn) = json.get("asn") {
        if let Some(asn) = asn.as_str() {
            asn.to_string().replace("AS", "").parse::<u32>().unwrap_or(0)
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let org = if let Some(org) = json.get("org") {
        if let Some(org) = org.as_str() {
            org.to_string()
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let lat = if let Some(lat) = json.get("latitude") {
        if let Some(lat) = lat.as_f64() {
            lat.to_string()
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    let lon = if let Some(lng) = json.get("longitude") {
        if let Some(lng) = lng.as_f64() {
            lng.to_string()
        } else {
            return failed_ip_result("IpCheck.ing");
        }
    } else {
        return failed_ip_result("IpCheck.ing");
    };

    IpResult {
        success: true,
        provider: "IpCheck.ing".to_string(),
        ip: Some(ip),
        autonomous_system: Some(AS {
            number: asn as u32,
            name: org,
        }),
        region: Some(Region {
            country: Some(country),
            region: Some(region),
            city: Some(city),
            coordinates: Some(Coordinates { lat, lon }),
            time_zone: None,
        }),
        risk: None,
    }
}
