#![allow(rustdoc::bare_urls)]
//! WireWrench - A command-line tool for interacting with web shells by injecting commands into URLs
//! 
//! This tool was created to save time from retyping commands while testing URL injections and parameter based web shells
//! Command line arguments for WireWrench
//! 
//! # Examples
//! 
//! Basic usage with default injection point:
//! ```shell
//! wirewrench https://example.com/path?param=BLUB
//! ```
//! 
//! Custom injection point:
//! ```shell
//! wirewrench -i INJECT https://example.com/path?param=INJECT
use clap::Parser;
use url::Url;
use std::process;
mod error_handling;
mod openings;
use error_handling::{WWError, InjectionPoint};
use rustyline::error::ReadlineError;
use openings::Opening;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The URL to send requests to, must contain an injection point
    /// 
    /// The URL should include an injection point marker (default: BLUB)
    /// that will be replaced with user input during execution.
    /// 
    /// Example: https://example.com/path?param=BLUB
    #[arg(required = true)]
    url: Url,

    /// Specify a different string to use as the injection point marker.
    /// Useful when the default 'BLUB' conflicts with the target URL.
    #[arg(short = 'i', long, default_value = "BLUB")]
    injection_point: InjectionPoint,

    /// Suppress the startup message
    #[arg(short = 's', long)]
    silence: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if let Err(err) = check_injection_point(&args.url, &args.injection_point) {
        WWError::display_error(&err);
        process::exit(1);
    }

    if !args.silence {
        Opening::random(&args.url);
    }
    let mut rl = rustyline::DefaultEditor::new()?;
    
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                if let Err(e) = send_request(&args.url, &line, &args.injection_point).await {
                    eprintln!("Request failed: {}", e);
                }
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("\nGoodbye!");
                break;
            },
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }
    
    Ok(())
}

/// Validates that the URL contains exactly one injection point
/// 
/// # Arguments
/// * `url` - The URL to check
/// * `injection` - The injection point marker to look for
/// 
/// # Returns
/// * `Ok(())` if exactly one injection point is found
/// * `Err(WWError)` if zero or multiple injection points are found
fn check_injection_point(url: &Url, injection: &InjectionPoint) -> Result<(), WWError> {
    let count = url.as_str().matches(injection.as_str()).count();
    match count {
        0 => Err(WWError::NoInjectionPoint(url.to_string(), injection.as_str().to_string())),
        1 => Ok(()),
        _ => Err(WWError::TooManyInjectionPoints(url.to_string(), injection.as_str().to_string())),
    }
}

/// Sends an HTTP GET request with the injected command
/// 
/// # Arguments
/// * `url` - The base URL containing the injection point
/// * `command` - The string to inject into the URL
/// * `injection` - The injection point marker to replace
/// 
/// # Returns
/// * `Ok(())` if the request was successful
/// * `Err(Box<dyn Error>)` if the request failed or returned a non-200 status
async fn send_request(url: &Url, command: &str, injection: &InjectionPoint) -> Result<(), Box<dyn std::error::Error>> {
    let injected_url = url.as_str().replace(injection.as_str(), command);
    let client = reqwest::Client::new();
    
    let response = client
        .get(&injected_url)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Request failed with status: {}", response.status()).into());
    }
    
    let body = response.text().await?;
    println!("{}", body);

    Ok(())
}