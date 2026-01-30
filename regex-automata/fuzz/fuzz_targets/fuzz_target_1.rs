#![no_main]

use regex_automata::dfa::regex::Regex;
use regex_automata::{Input, MatchError};

use libfuzzer_sys::arbitrary;

use libfuzzer_sys::{Corpus, fuzz_target};

#[derive(arbitrary::Arbitrary, Debug)]
pub struct PatternAndHaystack {
    pub pattern: String,
    pub haystack: String,
}



fuzz_target!(|data: PatternAndHaystack| {
    let Ok(re) = Regex::new(&data.pattern) else {
        return;
    };

    let input = Input::new(&data.haystack);

    type ME = MatchError;
    re.try_search(&input);

    println!("P::{}", data.pattern.escape_default());
    println!("H::{}", data.haystack.escape_default());
});
