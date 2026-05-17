#![no_main]

use regex_automata::dfa::regex::Regex;
use regex_automata::Input;

use libfuzzer_sys::arbitrary;

use libfuzzer_sys::{Corpus, fuzz_target};

const MAX_PATTERN_LEN: usize = 16 * 1024;
const MAX_HAYSTACK_LEN: usize = 16 * 1024;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct PatternAndHaystack {
    pub pattern: String,
    pub haystack: String,
}

fuzz_target!(|data: PatternAndHaystack| -> Corpus {
    if data.pattern.is_empty() && data.haystack.is_empty() {
        return Corpus::Reject;
    }
    if data.pattern.len() > MAX_PATTERN_LEN {
        return Corpus::Reject;
    }
    if data.haystack.len() > MAX_HAYSTACK_LEN {
        return Corpus::Reject;
    }

    let Ok(re) = Regex::new(&data.pattern) else {
        return Corpus::Reject;
    };

    let input = Input::new(&data.haystack);
    let result = re.try_search(&input);
    let _ = std::hint::black_box(result);

    Corpus::Keep
});
