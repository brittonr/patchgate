use super::support::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "dependency-graph-approved",
        setup: setup_approved,
        solve: solve_approved,
        check: check_approved,
    },
    Scenario {
        name: "dependency-graph-rejected",
        setup: setup_rejected,
        solve: solve_rejected,
        check: check_rejected,
    },
    Scenario {
        name: "dependency-graph-removed",
        setup: setup_removed,
        solve: solve_removed,
        check: check_removed,
    },
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Approved,
    Rejected,
    Removed,
}

impl Case {
    fn seed(self) -> u64 {
        match self {
            Self::Approved => 0x6a09_e667,
            Self::Rejected => 0xbb67_ae85,
            Self::Removed => 0x3c6e_f372,
        }
    }
}

struct Node {
    id: String,
    parents: Vec<String>,
    token: u64,
}

fn specification(case: Case) -> Vec<Node> {
    let mut state = case.seed();
    let mut nodes = Vec::new();
    let mut add = |id: String, parents: Vec<String>| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        nodes.push(Node {
            id,
            parents,
            token: state,
        });
    };
    add("root".into(), vec![]);
    add("independent-0".into(), vec![]);
    let depth = 7 + case.seed() as usize % 3;
    for index in 0..depth {
        let parent = if index == 0 {
            "root".into()
        } else {
            format!("chain-{}", index - 1)
        };
        add(format!("chain-{index}"), vec![parent]);
    }
    add("diamond-left".into(), vec!["root".into()]);
    add("independent-1".into(), vec!["independent-0".into()]);
    add("diamond-right".into(), vec!["root".into()]);
    add("side-root".into(), vec![]);
    add(
        "diamond-join".into(),
        vec!["diamond-left".into(), "diamond-right".into()],
    );
    add(
        "triple-join".into(),
        vec![
            format!("chain-{}", depth - 1),
            "diamond-join".into(),
            "side-root".into(),
        ],
    );
    add("independent-2".into(), vec!["independent-1".into()]);
    add("free".into(), vec![]);
    nodes
}

fn node_file(node: &Node, case: Case) -> String {
    let mut text = format!(
        "node {}\nseed {}\nvalue {:016x}\n",
        node.id,
        case.seed(),
        node.token
    );
    if node.id == "root" && case == Case::Rejected {
        text.push_str("SECRET=HARBOR_GRAPH_REJECT_ROOT\n");
    }
    text
}

fn edge_path(parent: &str, child: &str) -> String {
    format!("edge-{parent}-{child}.txt")
}

fn edge_text(parent: &Node, child: &Node, consumed: bool) -> String {
    let mut text = format!(
        "edge {} -> {}\nvalue {:016x}\n",
        parent.id, child.id, parent.token
    );
    if consumed {
        text.push_str(&format!("consumer {} {:016x}\n", child.id, child.token));
    }
    text
}

fn dependencies(repo: &Repo, hash: &str) -> Result<BTreeSet<String>> {
    static DEPENDENCY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\[(?:\d+|\*)\]\+?\s*([A-Z2-7]{53})").expect("valid dependency expression")
    });
    let text = repo.pijul(&["change", hash])?;
    let mut inside = false;
    let mut parents = BTreeSet::new();
    for line in text.lines() {
        if line.starts_with("# ") {
            inside = line.trim_end() == "# Dependencies";
        } else if inside {
            if let Some(capture) = DEPENDENCY.captures(line) {
                parents.insert(capture[1].to_owned());
            }
        }
    }
    Ok(parents)
}

fn setup(dir: &Path, signer: &Signer, case: Case) -> Result<Value> {
    let seed_text = format!("graph seed {}\n", case.seed());
    let repo = start(
        dir,
        signer,
        &[("POLICY.md", POLICY), ("graph-seed.txt", &seed_text)],
    )?;
    let base = repo.hashes("main")?;
    let nodes = specification(case);
    let mut hashes = BTreeMap::<String, String>::new();
    let mut facts = Vec::new();
    for node in &nodes {
        repo.write(&format!("node-{}.txt", node.id), &node_file(node, case))?;
        for parent_id in &node.parents {
            let parent = nodes
                .iter()
                .find(|parent| &parent.id == parent_id)
                .context("Unknown graph parent")?;
            repo.write(
                &edge_path(parent_id, &node.id),
                &edge_text(parent, node, true),
            )?;
        }
        for child in &nodes {
            if child.parents.contains(&node.id) {
                repo.write(
                    &edge_path(&node.id, &child.id),
                    &edge_text(node, child, false),
                )?;
            }
        }
        let hash = repo.record(&format!("Graph node {}", node.id))?;
        let actual: BTreeSet<_> = dependencies(&repo, &hash)?
            .difference(&base)
            .cloned()
            .collect();
        let expected: BTreeSet<_> = node.parents.iter().map(|id| hashes[id].clone()).collect();
        ensure!(
            actual == expected,
            "Actual Pijul edges differ for {}: {actual:?} != {expected:?}",
            node.id
        );
        facts.push(json!({"id": node.id, "hash": hash, "parents": actual}));
        hashes.insert(node.id.clone(), hash);
    }
    Ok(json!({"seed": case.seed(), "base": base, "root": hashes["root"], "nodes": facts}))
}

fn setup_approved(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, Case::Approved)
}
fn setup_rejected(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, Case::Rejected)
}
fn setup_removed(dir: &Path, signer: &Signer) -> Result<Value> {
    setup(dir, signer, Case::Removed)
}

fn fact_hashes(facts: &Value) -> Result<BTreeMap<String, String>> {
    facts["nodes"]
        .as_array()
        .context("Missing graph nodes")?
        .iter()
        .map(|node| {
            Ok((
                node["id"].as_str().context("Missing node id")?.to_owned(),
                node["hash"]
                    .as_str()
                    .context("Missing node hash")?
                    .to_owned(),
            ))
        })
        .collect()
}

fn affected(nodes: &[Node]) -> BTreeSet<String> {
    let mut blocked = BTreeSet::from(["root".to_owned()]);
    for node in nodes {
        if node.parents.iter().any(|parent| blocked.contains(parent)) {
            blocked.insert(node.id.clone());
        }
    }
    blocked
}

fn snapshot(repo: &Repo) -> Result<Value> {
    let main = repo.archive("main")?;
    let inbox = repo.archive("inbox")?;
    Ok(json!({
        "main": repo.hashes("main")?, "inbox": repo.hashes("inbox")?,
        "main_files": main.files, "inbox_files": inbox.files,
        "main_messages": main.messages, "inbox_messages": inbox.messages,
        "ledger": repo.ledger()?,
    }))
}

fn refuse(repo: &Repo, hash: &str) -> Result<()> {
    let before = snapshot(repo)?;
    let output = repo.gate(
        None,
        &[
            "accept",
            hash,
            "--reason",
            "Do not bypass absent prerequisites.",
        ],
        &[],
    )?;
    ensure!(
        !output.status.success(),
        "Human acceptance must fail for {hash}"
    );
    ensure!(
        snapshot(repo)? == before,
        "Human refusal must preserve channels, files, and audit records"
    );
    Ok(())
}

fn solve(dir: &Path, case: Case) -> Result<()> {
    let facts = load_facts(dir)?;
    let repo = Repo::open(dir.join("repo"));
    let hashes = fact_hashes(&facts)?;
    let nodes = specification(case);
    let blocked = affected(&nodes);
    let model = ModelServer::new(|request| {
        let decision = if request
            .body
            .to_string()
            .contains("HARBOR_GRAPH_REJECT_ROOT")
        {
            "reject"
        } else {
            "accept"
        };
        chat_reply(verdict(decision))
    })?;
    refuse(&repo, &hashes["triple-join"])?;
    if case == Case::Removed {
        checked_output(
            repo.gate(
                None,
                &[
                    "accept",
                    &hashes["root"],
                    "--reason",
                    "Accept the graph root.",
                ],
                &[],
            )?,
            "accept graph root",
        )?;
        repo.pijul(&["unrecord", "--channel", "main", &hashes["root"]])?;
        ensure!(
            repo.hashes("main")? == json_strings(&facts["base"])?,
            "The removed root must leave only base changes"
        );
    }
    checked_output(
        repo.gate(Some(&model), &["review"], &[])?,
        "review dependency graph",
    )?;
    let after = snapshot(&repo)?;
    for _ in 0..3 {
        checked_output(
            repo.gate(Some(&model), &["review"], &[])?,
            "repeat graph review",
        )?;
        ensure!(
            snapshot(&repo)? == after,
            "Repeated review must preserve channels, files, and audit records"
        );
    }
    if case == Case::Approved {
        refuse(&repo, &hashes["root"])?;
        refuse(&repo, &hashes["triple-join"])?;
    } else {
        for node in &nodes {
            if node.id != "root" && blocked.contains(&node.id) {
                refuse(&repo, &hashes[&node.id])?;
            }
        }
        checked_output(
            repo.gate(Some(&model), &["review"], &[])?,
            "review after human refusals",
        )?;
        ensure!(
            snapshot(&repo)? == after,
            "Refusals must not permit later graph changes"
        );
    }
    Ok(())
}

fn solve_approved(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, Case::Approved)?;
    let repo = Repo::open(dir.join("repo"));
    fs::write(
        dir.join("model-metrics.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario": "dependency-graph-approved",
            "control": "Oracle",
            "live": false,
            "main_hashes": repo.hashes("main")?,
            "inbox_hashes": repo.hashes("inbox")?,
            "records": repo.ledger()?,
        }))?,
    )?;
    Ok(())
}
fn solve_rejected(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, Case::Rejected)
}
fn solve_removed(dir: &Path, _: &RunOptions) -> Result<()> {
    solve(dir, Case::Removed)
}

fn json_strings(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .context("Expected a hash array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("Expected a hash string")
        })
        .collect()
}

fn expected_files(
    nodes: &[Node],
    included: &BTreeSet<String>,
    case: Case,
) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::from([
        ("POLICY.md".into(), POLICY.as_bytes().to_vec()),
        (
            "graph-seed.txt".into(),
            format!("graph seed {}\n", case.seed()).into_bytes(),
        ),
    ]);
    for node in nodes {
        if !included.contains(&node.id) {
            continue;
        }
        files.insert(
            format!("node-{}.txt", node.id),
            node_file(node, case).into_bytes(),
        );
        for child in nodes {
            if child.parents.contains(&node.id) {
                files.insert(
                    edge_path(&node.id, &child.id),
                    edge_text(node, child, included.contains(&child.id)).into_bytes(),
                );
            }
        }
    }
    files
}

fn check(check: &mut Check, case: Case) -> Result<()> {
    let nodes = specification(case);
    let hashes = fact_hashes(&check.facts)?;
    let base = json_strings(&check.facts["base"])?;
    let facts = check.facts["nodes"]
        .as_array()
        .context("Missing graph nodes")?
        .clone();
    let ids: BTreeSet<_> = nodes.iter().map(|node| node.id.clone()).collect();
    let actual_ids: BTreeSet<_> = hashes.keys().cloned().collect();
    check.require(
        actual_ids == ids && facts.len() == nodes.len(),
        "Facts must contain each fixed graph node once",
    );
    check.require(
        check.facts["seed"] == case.seed(),
        "Facts must contain the fixed graph seed",
    );
    check.require(!base.is_empty(), "The graph must have initial main hashes");
    let unique_hashes: BTreeSet<_> = hashes.values().cloned().collect();
    check.require(
        unique_hashes.len() == nodes.len() && base.is_disjoint(&unique_hashes),
        "Node hashes must be unique and separate from base hashes",
    );
    for node in &nodes {
        let hash = hashes.get(&node.id).context("Missing expected node hash")?;
        let fact = facts
            .iter()
            .find(|fact| fact["id"] == node.id)
            .context("Missing expected graph fact")?;
        let expected: BTreeSet<_> = node.parents.iter().map(|id| hashes[id].clone()).collect();
        let actual = dependencies(&check.repo, hash)?;
        let non_base: BTreeSet<_> = actual.difference(&base).cloned().collect();
        check.require(
            non_base == expected,
            format!("{} must have its actual Pijul prerequisites", node.id),
        );
        check.require(
            json_strings(&fact["parents"])? == expected,
            format!("{} facts must match actual graph edges", node.id),
        );
    }
    let blocked = affected(&nodes);
    let main_ids: BTreeSet<_> = ids
        .iter()
        .filter(|id| case == Case::Approved || !blocked.contains(*id))
        .cloned()
        .collect();
    for (channel, included) in [("main", &main_ids), ("inbox", &ids)] {
        let mut expected_hashes = base.clone();
        expected_hashes.extend(included.iter().map(|id| hashes[id].clone()));
        let log = check
            .repo
            .pijul(&["log", "--channel", channel, "--hash-only"])?;
        let entries: Vec<_> = log.split_whitespace().collect();
        let actual_hashes: BTreeSet<_> = entries.iter().map(|hash| (*hash).to_owned()).collect();
        check.require(
            actual_hashes == expected_hashes && entries.len() == expected_hashes.len(),
            format!("{channel} must contain exactly its dependency closure once"),
        );
        let archive = check.repo.archive(channel)?;
        check.require(
            archive.files == expected_files(&nodes, included, case),
            format!("{channel} must contain exactly the graph files and contents"),
        );
        check.require(
            !archive.messages.to_ascii_lowercase().contains("conflict"),
            format!("{channel} must have no graph conflicts"),
        );
    }
    let ledger = check.repo.ledger()?;
    let mut expected_records = 0;
    for node in &nodes {
        let history: Vec<_> = ledger
            .iter()
            .filter(|record| record["hash"] == hashes[&node.id])
            .collect();
        let expected = if node.id == "root" && case == Case::Rejected {
            Some(("reject", "model"))
        } else if node.id == "root" && case == Case::Removed {
            Some(("accept", "human"))
        } else if main_ids.contains(&node.id) {
            Some(("accept", "model"))
        } else {
            None
        };
        match expected {
            Some((decision, by)) => {
                expected_records += 1;
                check.require(
                    history.len() == 1,
                    format!("{} must have exactly one decision", node.id),
                );
                if let Some(record) = history.first() {
                    check.require(
                        record["decision"] == decision && record["by"] == by,
                        format!("{} must have its exact decision and author", node.id),
                    );
                    check.require(
                        record["message"] == format!("Graph node {}", node.id),
                        format!("{} audit message must match the actual change", node.id),
                    );
                    check.require(
                        record["reason"]
                            .as_str()
                            .is_some_and(|reason| !reason.is_empty())
                            && record["at"].as_str().is_some_and(|at| !at.is_empty()),
                        format!("{} must have a complete audit record", node.id),
                    );
                    check.require(
                        record.get("conflict").is_none_or(|value| value == false)
                            && record.get("merge").is_none_or(Value::is_null),
                        format!("{} must not claim a graph conflict or merge", node.id),
                    );
                    if by == "model" {
                        check.require(
                            record["model"]
                                .as_str()
                                .is_some_and(|model| !model.is_empty()),
                            format!("{} must identify its review model", node.id),
                        );
                    } else {
                        check.require(
                            record["user"].as_str().is_some_and(|user| !user.is_empty()),
                            format!("{} must identify its human author", node.id),
                        );
                    }
                }
            }
            None => check.require(
                history.is_empty(),
                format!("{} must have no decision while a root is absent", node.id),
            ),
        }
    }
    check.require(
        ledger.len() == expected_records,
        "The ledger must have no duplicate or extra graph decisions",
    );
    Ok(())
}

fn check_approved(checker: &mut Check) -> Result<()> {
    check(checker, Case::Approved)
}
fn check_rejected(checker: &mut Check) -> Result<()> {
    check(checker, Case::Rejected)
}
fn check_removed(checker: &mut Check) -> Result<()> {
    check(checker, Case::Removed)
}
