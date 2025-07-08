pub struct Opening {}
use rand::seq::IndexedRandom;
use url::Url;

static QUOTES: &[&str] = &[
    "Try to spend as much time on the computer as possible, after you die you won't have access to it anymore.",
    "Choose a major you love and you'll never work a day in your life because that field isn't hiring.",
    "Almost forgot that this is the whole point.",
    "Ranking of jobs that won't be taken over by AI: 1st place: Unemployed",
    "Do you know who's the most amazing person in the world? Read the first word."
    // I would like to see more suggestions in pull requests
];

impl Opening {
    fn base(url: &Url) {
        println!("WireWrench v{}", env!("CARGO_PKG_VERSION"));
        println!("https://github.com/amrosia/wirewrench");
        println!("Using url: {}", url);
    }

    pub fn random(url: &Url) {
        Self::base(url);
        let random_quote = QUOTES.choose(&mut rand::rng()).unwrap();

        println!("{}\n", random_quote)
    }
}