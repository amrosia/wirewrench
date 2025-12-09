#![allow(rustdoc::bare_urls)]
//! WireWrench - A command-line tool for interacting with web shells by injecting commands into URLs
//! 
//! This tool was created to save time from retyping commands while testing URL injections and parameter-based web shells.
//! 
//! # Examples
//! 
//! Basic usage with default injection point:
//! ```shell
//! ww https://example.com/path?param=BLUB
//! ```
//! 
//! Custom injection point:
//! ```shell
//! ww -i INJECT https://example.com/path?param=INJECT
use clap::Parser;
use url::Url;
use std::process;
mod error_handling;
mod openings;
use error_handling::{WWError, InjectionPoint};
use rustyline::error::ReadlineError;
use openings::Opening;
use diff;

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

    /// Only show changes from the first command's output.
    /// The first request's output is stored as a baseline; subsequent requests
    /// will display only the characters that differ from that baseline.
    /// To avoid showing garbage content, the first command should be
    /// something minimal (e.g., an empty command) so that the baseline contains
    /// only the static parts of the page.
    #[arg(short = 'd', long)]
    diff: bool,
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
    let mut baseline = None;
    
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                rl.add_history_entry(&line)?;
                if let Err(e) = send_request(&args.url, &line, &args.injection_point, &mut baseline, args.diff).await {
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

fn check_injection_point(url: &Url, injection: &InjectionPoint) -> Result<(), WWError> {
    let count = url.as_str().matches(injection.as_str()).count();
    match count {
        0 => Err(WWError::NoInjectionPoint(url.to_string(), injection.as_str().to_string())),
        1 => Ok(()),
        _ => Err(WWError::TooManyInjectionPoints(url.to_string(), injection.as_str().to_string())),
    }
}

/// Extract the dynamic part (inserted characters) from the diff between baseline and current.
/// Returns a string containing only the characters that are new in `b` compared to `a`.
fn extract_dynamic(a: &str, b: &str) -> String {
    let diff_result = diff::chars(a, b);
    let mut dynamic = String::new();
    for change in diff_result {
        match change {
            diff::Result::Right(r) => dynamic.push(r),
            _ => (),
        }
    }
    dynamic
}


async fn send_request(
    url: &Url,
    command: &str,
    injection: &InjectionPoint,
    baseline: &mut Option<String>,
    diff: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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

    if diff {
        match baseline {
            None => {
                *baseline = Some(body.clone());
                println!("{}", body);
            }
            Some(bl) => {
                let dynamic = extract_dynamic(bl, &body);
                if dynamic.is_empty() {
                    println!("(no changes)");
                } else {
                    println!("{}", dynamic);
                }
            }
        }
    } else {
        println!("{}", body);
    }

    Ok(())
}