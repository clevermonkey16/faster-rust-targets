use std::env;

use regex_automata::dfa::regex::Regex;
use regex_automata::{Input, MatchError};

use unescaper::unescape;

fn main() {
    let mut args = env::args();

    let pattern = args.next().expect("Missing arg for pattern");
    let haystack = args.next().expect("Missing arg for haystack");

    let pattern = unescape(&pattern).unwrap();
    let haystack = unescape(&haystack).unwrap();

    let Ok(re) = Regex::new(&pattern) else {
        return;
    };

    let input = Input::new(&haystack);

    type ME = MatchError;
    let _ = re.try_search(&input);
}
