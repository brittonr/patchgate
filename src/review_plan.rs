use std::io::{self, Write};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::{RawValue, to_raw_value};
use sha2::{Digest, Sha256};

use crate::pijul::{NativeContextFile, NativeVertex, NativeVertexKind, ReviewChange};
use crate::review::ReviewBinding;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRange {
    pub path: String,
    pub change: String,
    pub start: u64,
    pub end: u64,
}

pub struct Plan<'a> {
    candidate: &'a ReviewChange,
    binding: &'a ReviewBinding,
    source_sha256: String,
    unchanged: Vec<Unchanged<'a>>,
    pages: Vec<Page>,
    core_chars: usize,
    max_page_chars: usize,
    unchanged_bytes: usize,
}

struct Unchanged<'a> {
    path: &'a str,
    vertex: &'a NativeVertex,
    framing: usize,
}

struct Page {
    fragments: Vec<Fragment>,
    chars: usize,
}

struct Fragment {
    unchanged: usize,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct WindowInput<'a> {
    schema_version: u8,
    candidate: ChangedCandidate<'a>,
    binding: &'a ReviewBinding,
    coverage: Coverage<'a>,
    context_window: Window<'a>,
}

struct ChangedCandidate<'a>(&'a ReviewChange);
struct ChangedContext<'a>(&'a [NativeContextFile]);
struct ChangedFiles<'a>(&'a [NativeContextFile]);
struct ChangedVertices<'a>(&'a [NativeVertex]);

#[derive(Serialize)]
struct Coverage<'a> {
    source_sha256: &'a str,
    page: usize,
    pages: usize,
    changed_context_complete: bool,
}

struct Window<'a> {
    unchanged: &'a [Unchanged<'a>],
    fragments: &'a [Fragment],
}

#[derive(Serialize)]
struct WindowFragment<'a> {
    path: &'a str,
    change: &'a str,
    start: u64,
    end: u64,
    kind: &'static str,
    text: &'a str,
}

impl Serialize for ChangedCandidate<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let candidate = self.0;
        let mut state = serializer.serialize_struct("Candidate", 8)?;
        state.serialize_field("hash", &candidate.hash)?;
        state.serialize_field("message", &candidate.message)?;
        state.serialize_field("authors", &candidate.authors)?;
        state.serialize_field("timestamp", &candidate.timestamp)?;
        state.serialize_field("dependencies", &candidate.dependencies)?;
        state.serialize_field("paths", &candidate.paths)?;
        state.serialize_field("context", &ChangedContext(&candidate.context.files))?;
        state.serialize_field("metadata_context", &candidate.metadata_context)?;
        state.end()
    }
}

impl Serialize for ChangedContext<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Context", 2)?;
        state.serialize_field("full", &false)?;
        state.serialize_field("files", &ChangedFiles(self.0))?;
        state.end()
    }
}

impl Serialize for ChangedFiles<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut files = serializer.serialize_seq(Some(self.0.len()))?;
        for file in self.0 {
            #[derive(Serialize)]
            struct File<'a> {
                path: &'a str,
                vertices: ChangedVertices<'a>,
            }
            files.serialize_element(&File {
                path: &file.path,
                vertices: ChangedVertices(&file.vertices),
            })?;
        }
        files.end()
    }
}

impl Serialize for ChangedVertices<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut vertices = serializer.serialize_seq(None)?;
        for vertex in self.0 {
            if !matches!(vertex.kind, NativeVertexKind::Keep) {
                vertices.serialize_element(vertex)?;
            }
        }
        vertices.end()
    }
}

impl Serialize for Window<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fragments = serializer.serialize_seq(Some(self.fragments.len()))?;
        for fragment in self.fragments {
            let unchanged = &self.unchanged[fragment.unchanged];
            fragments.serialize_element(&WindowFragment {
                path: unchanged.path,
                change: &unchanged.vertex.change,
                start: unchanged.vertex.start + fragment.start as u64,
                end: unchanged.vertex.start + fragment.end as u64,
                kind: "keep",
                text: &unchanged.vertex.text[fragment.start..fragment.end],
            })?;
        }
        fragments.end()
    }
}

#[derive(Default)]
struct CharacterCount(usize);

impl Write for CharacterCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.iter().filter(|&&byte| byte & 0xc0 != 0x80).count();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encoded_chars(value: &impl Serialize) -> serde_json::Result<usize> {
    let mut count = CharacterCount::default();
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

fn digits(value: usize) -> usize {
    value.checked_ilog10().map_or(1, |power| power as usize + 1)
}

fn coordinate_digits(value: u64) -> usize {
    value.checked_ilog10().map_or(1, |power| power as usize + 1)
}

fn escaped_chars(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{08}' | '\t' | '\n' | '\u{0c}' | '\r' => 2,
        '\u{00}'..='\u{1f}' => 6,
        _ => 1,
    }
}

impl<'a> Plan<'a> {
    pub fn new(
        candidate: &'a ReviewChange,
        binding: &'a ReviewBinding,
        full_input: &str,
        limit: usize,
    ) -> std::result::Result<Self, String> {
        if !candidate.context.full {
            return Err("Bounded review requires complete native context".into());
        }
        let mut unchanged = Vec::new();
        let mut unchanged_bytes = 0usize;
        for file in &candidate.context.files {
            for vertex in &file.vertices {
                let bytes = u64::try_from(vertex.text.len())
                    .map_err(|_| "Native span exceeds the coordinate limit")?;
                if vertex.end.checked_sub(vertex.start) != Some(bytes) {
                    return Err(format!("Native span has invalid byte coordinates: {}", file.path));
                }
                if matches!(vertex.kind, NativeVertexKind::Keep) {
                    let framing = encoded_chars(&WindowFragment {
                        path: &file.path,
                        change: &vertex.change,
                        start: vertex.start,
                        end: vertex.start,
                        kind: "keep",
                        text: "",
                    })
                    .map_err(|error| error.to_string())?
                        - 2 * coordinate_digits(vertex.start);
                    unchanged_bytes = unchanged_bytes
                        .checked_add(vertex.text.len())
                        .ok_or("Native context exceeds the byte count limit")?;
                    unchanged.push(Unchanged {
                        path: &file.path,
                        vertex,
                        framing,
                    });
                }
            }
        }
        let mut plan = Self {
            candidate,
            binding,
            source_sha256: format!("{:x}", Sha256::digest(full_input.as_bytes())),
            unchanged,
            pages: Vec::new(),
            core_chars: 0,
            max_page_chars: 0,
            unchanged_bytes,
        };
        plan.core_chars = encoded_chars(&plan.window_input(0, 1, &[]))
            .map_err(|error| error.to_string())?;
        if plan.core_chars > limit {
            return Err("The complete changed core exceeds the structured input limit".into());
        }
        let mut page_digits = 1;
        loop {
            let pages = plan.pack(limit, page_digits)?;
            let final_digits = digits(pages.len());
            if final_digits == page_digits {
                plan.max_page_chars = pages.iter().map(|page| page.chars).max().unwrap();
                plan.pages = pages;
                return Ok(plan);
            }
            page_digits = final_digits;
        }
    }

    pub fn len(&self) -> usize {
        self.pages.len()
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// This count includes an empty window and one-digit page fields.
    pub fn core_chars(&self) -> usize {
        self.core_chars
    }

    pub fn max_page_chars(&self) -> usize {
        self.max_page_chars
    }

    pub fn unchanged_bytes(&self) -> usize {
        self.unchanged_bytes
    }

    pub fn input(&self, index: usize) -> serde_json::Result<Box<RawValue>> {
        let page = self.pages.get(index).ok_or_else(|| {
            serde_json::Error::io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Context window index is outside the plan",
            ))
        })?;
        to_raw_value(&self.window_input(index, self.pages.len(), &page.fragments))
    }

    pub fn ranges(&self, index: usize) -> Vec<ContextRange> {
        self.pages[index]
            .fragments
            .iter()
            .map(|fragment| {
                let unchanged = &self.unchanged[fragment.unchanged];
                ContextRange {
                    path: unchanged.path.to_owned(),
                    change: unchanged.vertex.change.clone(),
                    start: unchanged.vertex.start + fragment.start as u64,
                    end: unchanged.vertex.start + fragment.end as u64,
                }
            })
            .collect()
    }

    fn window_input<'b>(
        &'b self,
        page: usize,
        pages: usize,
        fragments: &'b [Fragment],
    ) -> WindowInput<'b> {
        WindowInput {
            schema_version: 2,
            candidate: ChangedCandidate(self.candidate),
            binding: self.binding,
            coverage: Coverage {
                source_sha256: &self.source_sha256,
                page,
                pages,
                changed_context_complete: true,
            },
            context_window: Window {
                unchanged: &self.unchanged,
                fragments,
            },
        }
    }

    fn pack(&self, limit: usize, page_digits: usize) -> Result<Vec<Page>, String> {
        let mut pages = Vec::new();
        let mut page = self.empty_page(0, page_digits);
        for (index, unchanged) in self.unchanged.iter().enumerate() {
            let text = &unchanged.vertex.text;
            let mut start = 0;
            loop {
                let available = limit.saturating_sub(page.chars);
                let separator = usize::from(!page.fragments.is_empty());
                let native_start = unchanged.vertex.start + start as u64;
                let fixed = unchanged.framing + coordinate_digits(native_start) + separator;
                let mut end = start;
                let mut text_chars = 0;
                let mut cost = fixed + coordinate_digits(native_start);
                for character in text[start..].chars() {
                    let next_end = end + character.len_utf8();
                    let next_text_chars = text_chars + escaped_chars(character);
                    let next_cost = fixed
                        + coordinate_digits(unchanged.vertex.start + next_end as u64)
                        + next_text_chars;
                    if next_cost > available {
                        break;
                    }
                    end = next_end;
                    text_chars = next_text_chars;
                    cost = next_cost;
                }
                if cost > available || (end == start && !text.is_empty()) {
                    if page.fragments.is_empty() {
                        return Err(
                            "The complete changed core leaves no space for an unchanged native fragment"
                                .into(),
                        );
                    }
                    pages.push(page);
                    page = self.empty_page(pages.len(), page_digits);
                    continue;
                }
                page.chars += cost;
                page.fragments.push(Fragment {
                    unchanged: index,
                    start,
                    end,
                });
                if end == text.len() {
                    break;
                }
                start = end;
                pages.push(page);
                page = self.empty_page(pages.len(), page_digits);
            }
        }
        if page.chars > limit {
            return Err("The complete changed core exceeds the structured input limit".into());
        }
        pages.push(page);
        Ok(pages)
    }

    fn empty_page(&self, index: usize, page_digits: usize) -> Page {
        Page {
            fragments: Vec::new(),
            chars: self.core_chars + digits(index) - 1 + page_digits - 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{Value, json};

    use super::*;
    use crate::pijul::{MetadataContext, NativeContext};
    use crate::review::{self, MainBinding};

    fn vertex(kind: NativeVertexKind, change: &str, start: u64, text: &str) -> NativeVertex {
        NativeVertex {
            change: change.into(),
            start,
            end: start + text.len() as u64,
            kind,
            text: text.into(),
        }
    }

    fn candidate(text: &str) -> ReviewChange {
        ReviewChange {
            hash: "candidate".into(),
            message: "Change café 🛡".into(),
            authors: vec!["Author".into()],
            timestamp: "2026-10-25T00:00:00Z".into(),
            dependencies: vec!["origin".into()],
            paths: BTreeSet::from(["café/🛡.rs".into(), "empty".into()]),
            context: NativeContext {
                full: true,
                files: vec![
                    NativeContextFile {
                        path: "café/🛡.rs".into(),
                        vertices: vec![
                            vertex(NativeVertexKind::Keep, "origin", 98, text),
                            vertex(NativeVertexKind::Del, "origin", 800, "old\n"),
                            vertex(NativeVertexKind::Add, "candidate", 0, "new\n"),
                            vertex(NativeVertexKind::Keep, "origin", 900, "tail 🛡\n"),
                        ],
                    },
                    NativeContextFile {
                        path: "empty".into(),
                        vertices: vec![
                            vertex(NativeVertexKind::Keep, "origin", 77, ""),
                            vertex(NativeVertexKind::Add, "candidate", 44, ""),
                            vertex(NativeVertexKind::Del, "origin", 55, ""),
                        ],
                    },
                ],
            },
            metadata_context: vec![MetadataContext {
                path: "mode".into(),
                before: Some("regular".into()),
                after: Some("executable".into()),
            }],
        }
    }

    fn binding() -> ReviewBinding {
        ReviewBinding {
            candidates: vec!["candidate".into()],
            policy: None,
            main: MainBinding {
                channel: "main".into(),
                state: Some("main-state".into()),
            },
        }
    }

    fn assert_coverage(plan: &Plan<'_>, limit: usize) {
        let mut expected = plan.unchanged.iter();
        let mut current = expected.next();
        let mut offset = 0;
        let mut maximum = 0;
        let mut bytes = 0;
        let original = serde_json::to_value(plan.candidate).unwrap();
        for index in 0..plan.len() {
            let input = plan.input(index).unwrap();
            let chars = input.get().chars().count();
            maximum = maximum.max(chars);
            assert!(chars <= limit, "page {index}: {chars} > {limit}");
            let value: Value = serde_json::from_str(input.get()).unwrap();
            assert_eq!(value["schema_version"], 2);
            assert_eq!(value["candidate"]["context"]["full"], false);
            for field in [
                "hash", "message", "authors", "timestamp", "dependencies", "paths",
                "metadata_context",
            ] {
                assert_eq!(value["candidate"][field], original[field]);
            }
            assert_eq!(value["binding"], serde_json::to_value(plan.binding).unwrap());
            assert_eq!(value["coverage"], json!({
                "source_sha256": plan.source_sha256(),
                "page": index,
                "pages": plan.len(),
                "changed_context_complete": true,
            }));
            for (file_index, file) in plan.candidate.context.files.iter().enumerate() {
                let changed: Vec<_> = file.vertices.iter()
                    .filter(|vertex| !matches!(vertex.kind, NativeVertexKind::Keep))
                    .map(|vertex| serde_json::to_value(vertex).unwrap())
                    .collect();
                let actual = &value["candidate"]["context"]["files"][file_index];
                assert_eq!(actual["path"], file.path);
                assert_eq!(actual["vertices"], json!(changed));
            }
            let fragments = value["context_window"].as_array().unwrap();
            let ranges = plan.ranges(index);
            assert_eq!(ranges.len(), fragments.len());
            for (fragment, range) in fragments.iter().zip(ranges) {
                let unchanged = current.expect("unexpected fragment");
                let text = fragment["text"].as_str().unwrap();
                let end = offset + text.len();
                assert_eq!(text, &unchanged.vertex.text[offset..end]);
                assert_eq!(fragment["path"], unchanged.path);
                assert_eq!(fragment["change"], unchanged.vertex.change);
                assert_eq!(fragment["kind"], "keep");
                assert_eq!(fragment["start"], unchanged.vertex.start + offset as u64);
                assert_eq!(fragment["end"], unchanged.vertex.start + end as u64);
                assert_eq!(range, ContextRange {
                    path: unchanged.path.into(),
                    change: unchanged.vertex.change.clone(),
                    start: unchanged.vertex.start + offset as u64,
                    end: unchanged.vertex.start + end as u64,
                });
                bytes += text.len();
                offset = end;
                if offset == unchanged.vertex.text.len() {
                    current = expected.next();
                    offset = 0;
                }
            }
        }
        assert!(current.is_none(), "native context is incomplete");
        assert_eq!(bytes, plan.unchanged_bytes());
        assert_eq!(maximum, plan.max_page_chars());
    }

    #[test]
    fn exact_coverage_repeats_changed_core_and_preserves_empty_spans() {
        let candidate = candidate(&"first\nsecond\n".repeat(300));
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let plan = Plan::new(&candidate, &binding, source.get(), 1450).unwrap();
        assert!(plan.len() > 2);
        assert_eq!(plan.source_sha256(), format!("{:x}", Sha256::digest(source.get())));
        assert_coverage(&plan, 1450);
        assert!(plan.input(plan.len()).is_err());
    }

    #[test]
    fn unicode_fragments_use_native_byte_coordinates() {
        let candidate = candidate(&"é中🛡\n".repeat(150));
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let plan = Plan::new(&candidate, &binding, source.get(), 1410).unwrap();
        assert!(plan.len() > 1);
        assert_coverage(&plan, 1410);
        assert!(plan.ranges(0)[0].end > 100);
    }

    #[test]
    fn escape_costs_match_json_for_every_control_character() {
        let text: String = (0..=31).map(char::from).chain(['"', '\\', '/', 'é', '🛡']).collect();
        let expected = serde_json::to_string(&text).unwrap().chars().count() - 2;
        assert_eq!(text.chars().map(escaped_chars).sum::<usize>(), expected);
        let candidate = candidate(&text.repeat(90));
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let plan = Plan::new(&candidate, &binding, source.get(), 1440).unwrap();
        assert!(plan.len() > 9);
        assert_coverage(&plan, 1440);
    }

    #[test]
    fn exact_single_character_bound_and_one_character_short() {
        let mut candidate = candidate("🛡");
        candidate.context.files.truncate(1);
        candidate.context.files[0].vertices.truncate(1);
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let generous = Plan::new(&candidate, &binding, source.get(), usize::MAX).unwrap();
        let exact = generous.max_page_chars();
        let plan = Plan::new(&candidate, &binding, source.get(), exact).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.max_page_chars(), exact);
        assert_coverage(&plan, exact);
        assert!(Plan::new(&candidate, &binding, source.get(), exact - 1).is_err());
    }

    #[test]
    fn page_count_digit_transitions_remain_bounded() {
        let mut candidate = candidate(&"a".repeat(210));
        candidate.context.files.truncate(1);
        candidate.context.files[0].vertices.truncate(1);
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let generous = Plan::new(&candidate, &binding, source.get(), usize::MAX).unwrap();
        let keep = &generous.unchanged[0];
        let limit = generous.core_chars() + keep.framing + 3 + 3 + 5;
        let plan = Plan::new(&candidate, &binding, source.get(), limit).unwrap();
        assert!(plan.len() >= 10);
        assert_coverage(&plan, limit);
    }

    #[test]
    fn oversized_core_and_invalid_coordinates_fail() {
        let mut candidate = candidate("unchanged");
        candidate.context.files[0].vertices[2].text = "large changed core".repeat(1000);
        candidate.context.files[0].vertices[2].end =
            candidate.context.files[0].vertices[2].text.len() as u64;
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        assert!(Plan::new(&candidate, &binding, source.get(), 1500).is_err());
        candidate.context.files[0].vertices[0].end += 1;
        assert!(Plan::new(&candidate, &binding, source.get(), usize::MAX).is_err());
        candidate.context.full = false;
        assert!(Plan::new(&candidate, &binding, source.get(), usize::MAX).is_err());
    }

    #[test]
    fn core_without_unchanged_text_can_use_the_exact_limit() {
        let mut candidate = candidate("");
        for file in &mut candidate.context.files {
            file.vertices.retain(|vertex| !matches!(vertex.kind, NativeVertexKind::Keep));
        }
        let binding = binding();
        let source = review::input(&candidate, &binding).unwrap();
        let generous = Plan::new(&candidate, &binding, source.get(), usize::MAX).unwrap();
        let plan = Plan::new(&candidate, &binding, source.get(), generous.core_chars()).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.unchanged_bytes(), 0);
        assert_coverage(&plan, generous.core_chars());
    }

}
