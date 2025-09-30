// src/utils/report.rs

// 引入 regex 库
use regex::Regex;
// 引入 reqwest 客户端
use reqwest::Client;
// 引入 Mutex 用于线程安全
use std::sync::{LazyLock, Mutex};
// 引入 Duration 用于超时
use std::time::Duration;

// 获取使用次数
pub async fn get_usage_count() -> Result<(u64, u64), String> {
    // 创建一个新的 reqwest 客户端
    let client = Client::new();
    // 发送 GET 请求并获取响应文本
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

    // 使用正则表达式匹配数字
    let re = Regex::new(r"\d+\s/\s\d+").unwrap();
    let line = if let Some(text) = re.find(&text) {
        text.as_str()
    } else {
        return Err("Can not parse response".to_string());
    };

    // 分割字符串并解析为 u64
    let vec = line.split('/').collect::<Vec<&str>>();

    Ok((
        vec[0].trim().parse::<u64>().unwrap(),
        vec[1].trim().parse::<u64>().unwrap(),
    ))
}

pub static GLOBAL_STRING: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));

// 定义一个宏，用于向全局字符串中打印内容
#[macro_export]
macro_rules! global_print {
    ($($arg:tt)*) => {{
        let mut global_string = GLOBAL_STRING.lock().unwrap();
        write!(global_string, $($arg)*).expect("Failed to write to global string");
    }}
}

// 定义一个宏，用于向全局字符串中打印内容并换行
#[macro_export]
macro_rules! global_println {
    ($($arg:tt)*) => {{
        let mut global_string = GLOBAL_STRING.lock().unwrap();
        writeln!(global_string, $($arg)*).expect("Failed to write to global string");
    }}
}

// 将内容上传到 pastebin
#[allow(clippy::await_holding_lock)]
pub async fn _post_to_pastebin() -> Result<String, String> {
    // https://pastebin.highp.ing
    // 从环境变量中获取 pastebin 的 URL
    let Some(url) = option_env!("CROSS_PASTEDIN_URL") else {
        return Err(
            "Upload: Compiling without specifying `CROSS_PASTEDIN_URL` will now skip Pastebin uploads"
                .to_string(),
        );
    };

    // If you see this password, please do not share it with others. (๑•̀ㅂ•́)و✧
    // 从环境变量中获取 pastebin 的密钥
    let Some(secret) = option_env!("CROSS_PASTEDIN_SECRET") else {
        return Err(
            "Upload: Compiling without specifying `CROSS_PASTEDIN_SECRET` will now skip Pastebin uploads"
                .to_string(),
        );
    };

    // 创建一个新的 reqwest 客户端
    let client = Client::new();
    // 发送 POST 请求
    let resp = client
        .post(format!("{url}/upload"))
        .header("Authorization", secret)
        .body(GLOBAL_STRING.lock().unwrap().clone())
        .send()
        .await;
    // 解析响应文本
    let text = if let Ok(res) = resp {
        if !res.status().is_success() {
            return Err("Upload: You have no permission to upload".to_string());
        }
        match res.text().await {
            Ok(text) => text,
            Err(_) => return Err("Upload: Can not parse response".to_string()),
        }
    } else {
        return Err("Upload: Can not parse response".to_string());
    };

    // 解析 ID 并返回 URL
    let id = text.trim().parse::<String>().unwrap();
    Ok(format!("{url}/{id}"))
}
