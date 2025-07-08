use ariadne::{Label, Report, ReportKind, Source};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum WWError {
    // Using any other number of points than 1 serves no purpose and breaks the whole point 
    NoInjectionPoint(String, String),  // (url, injection_point)
    TooManyInjectionPoints(String, String),  // (url, injection_point)
}

impl Error for WWError {}

impl fmt::Display for WWError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WWError::NoInjectionPoint(url, injection) => 
                write!(f, "No injection point '{}' found in URL: {}", injection, url),
            WWError::TooManyInjectionPoints(url, injection) => 
                write!(f, "Too many '{}' injection points in URL: {}", injection, url),
        }
    }
}

// This is here so that underlining of each supplied point would match its length.
fn find_injection_positions(s: &str, injection: &str) -> Vec<(usize, usize)> {
    s.match_indices(injection)
        .map(|(start, matched)| (start, start + matched.len()))
        .collect()
}

impl WWError { 
    pub fn display_error(err: &WWError) {
        match err {
            WWError::NoInjectionPoint(url, injection) => {
                Report::build(ReportKind::Error, "URL", 1)
                    .with_message("invalid URL syntax")
                    .with_label(
                        Label::new(("URL", 0..url.len()))
                            .with_message(format!("where is the injection point '{}'?", injection))
                    )
                    .with_help(format!("Add the injection point '{}' somewhere in your URL", injection))
                    .finish()
                    .print(("URL", Source::from(url)))
                    .unwrap();
            }

            WWError::TooManyInjectionPoints(url, injection) => {
                let positions = find_injection_positions(url, injection);
                let mut report = Report::build(ReportKind::Error, "URL", 1)
                    .with_message(format!("Too many '{}' injection points found!", injection));

                report = report.with_label(
                    Label::new(("URL", positions[0].0..positions[0].1))
                        .with_message("This one is ok")
                );

                for pos in positions.iter().skip(1) {
                    report = report.with_label(
                        Label::new(("URL", pos.0..pos.1))
                            .with_message("WHAT?!")
                    );
                }

                report
                    .with_help("Only one injection point is supported")
                    .finish()
                    .print(("URL", Source::from(url)))
                    .unwrap();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct InjectionPoint(pub String);

impl InjectionPoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Injection points with spaces make no sense and no use case
impl std::str::FromStr for InjectionPoint {
    type Err = &'static str;
  
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars().any(char::is_whitespace) {
            Err("Injection point cannot contain whitespace")
        } else {
            Ok(InjectionPoint(s.to_string()))
        }
    }
}