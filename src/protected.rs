// Match the original fnmatchcase patterns, including Unicode and literal braces.
pub fn pattern_regex(pattern: &str) -> String {
    let chars: Vec<_> = pattern.chars().collect();
    let mut result = String::from("(?s:\\A");
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        index += 1;
        match character {
            '*' => {
                result.push_str(".*");
                while chars.get(index) == Some(&'*') {
                    index += 1;
                }
            }
            '?' => result.push('.'),
            '[' => {
                let start = index;
                let negative = chars.get(index) == Some(&'!');
                let mut end = index + usize::from(negative);
                if chars.get(end) == Some(&']') {
                    end += 1;
                }
                while end < chars.len() && chars[end] != ']' {
                    end += 1;
                }
                if end == chars.len() {
                    result.push_str("\\[");
                    continue;
                }
                index = end + 1;
                let mut body = String::new();
                let mut cursor = start + usize::from(negative);
                while cursor < end {
                    if cursor + 2 < end && chars[cursor + 1] == '-' {
                        if chars[cursor] <= chars[cursor + 2] {
                            escape_class(&mut body, chars[cursor]);
                            body.push('-');
                            escape_class(&mut body, chars[cursor + 2]);
                        }
                        cursor += 3;
                    } else {
                        escape_class(&mut body, chars[cursor]);
                        cursor += 1;
                    }
                }
                if body.is_empty() {
                    result.push_str(if negative { "." } else { "\\b\\B" });
                } else {
                    result.push('[');
                    if negative {
                        result.push('^');
                    }
                    result.push_str(&body);
                    result.push(']');
                }
            }
            literal => {
                if matches!(
                    literal,
                    '\\' | '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | ']'
                ) {
                    result.push('\\');
                }
                result.push(literal);
            }
        }
    }
    result.push_str("\\z)");
    result
}

fn escape_class(output: &mut String, character: char) {
    if matches!(character, '\\' | '[' | ']' | '^' | '-' | '&' | '~') {
        output.push('\\');
    }
    output.push(character);
}

#[cfg(test)]
mod tests {
    use super::pattern_regex;
    use regex::Regex;

    #[test]
    fn protected_paths_match_characters_and_complete_paths() {
        for (pattern, path, expected) in [
            ("?.txt", "é.txt", true),
            ("?.txt", "ab.txt", false),
            ("src/*", "src/nested/main.rs", true),
            ("*.rs", "main.rs\n", false),
            ("policy*", "Policy.md", false),
            ("a{b}.txt", "a{b}.txt", true),
            ("a{b}.txt", "ab.txt", false),
            ("*", "line\nbreak", true),
            ("a\\b", "a\\b", true),
        ] {
            assert_eq!(
                Regex::new(&pattern_regex(pattern)).unwrap().is_match(path),
                expected,
                "{pattern:?}: {path:?}"
            );
        }
    }

    #[test]
    fn character_classes_keep_literal_and_range_semantics() {
        for (pattern, path, expected) in [
            ("[!a-c]", "é", true),
            ("[!a-c]", "b", false),
            ("[[]", "[", true),
            ("[]]", "]", true),
            ("[!]", "[!]", true),
            ("[z-a]", "z", false),
            ("[!z-a]", "z", true),
            ("[a-b-c]", "-", true),
            ("[a&&b]", "&", true),
            ("[-]", "-", true),
        ] {
            assert_eq!(
                Regex::new(&pattern_regex(pattern)).unwrap().is_match(path),
                expected,
                "{pattern:?}: {path:?}"
            );
        }
    }
}
