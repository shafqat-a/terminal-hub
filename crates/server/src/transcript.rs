//! Console transcript → chat turns.
//!
//! Splits a plain-text tmux capture (scrollback + screen, wrapped lines
//! re-joined) into question/answer pairs so a console that has been driven
//! from the full terminal UI shows up in the chat client as history.
//!
//! A *user* turn starts at a prompt line — the program's input marker
//! followed by what was typed:
//!
//! - shells: `user@host:~/dir$ cmd`, `# cmd`, `$ cmd`, `❯ cmd`
//! - Claude Code: `❯ question` (older builds: `> question`), continuation
//!   lines indented by two spaces
//! - REPLs: `>>> expr`, with `... more` continuation lines
//!
//! Everything between two prompt lines is the *assistant* turn, minus chrome
//! (box frames, spinner/timing lines, help hints, bare prompts). Heuristics,
//! not a grammar: a scrollback with redraw artefacts yields the occasional
//! odd turn, which is still far better than nothing on a phone.

/// One parsed question/answer pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    pub user: String,
    pub assistant: String,
}

fn is_box_char(c: char) -> bool {
    matches!(
        c,
        '─' | '│'
            | '┌'
            | '┐'
            | '└'
            | '┘'
            | '╭'
            | '╮'
            | '╰'
            | '╯'
            | '┃'
            | '║'
            | '═'
            | '╌'
            | '┄'
            | '━'
    )
}

fn core(line: &str) -> &str {
    line.trim_matches(|c: char| c.is_whitespace() || is_box_char(c))
}

/// Prompt characters that may end an input marker.
const PROMPT_CHARS: [char; 6] = ['$', '#', '%', '>', '❯', '»'];

/// If `line` is "<marker> <typed text>", return the typed text.
///
/// The marker is the leading run of non-space characters (≤ 60 chars) that
/// ends in a prompt character, or a Claude Code `❯`/`>` bullet. Arrows such
/// as `->`, `=>`, `-->` are not markers, nor are lines whose marker is
/// followed by nothing.
pub fn prompt_input(line: &str) -> Option<&str> {
    let line = line.trim_end();
    if line.starts_with(' ') {
        return None;
    }
    // Try every space-delimited prefix, shortest first, so "❯ a > b" yields
    // "a > b" while "(venv) user@h:~$ cmd" still finds its two-word prompt.
    for (pos, _) in line.match_indices(' ') {
        let marker = &line[..pos];
        if marker.chars().count() > 60 {
            break;
        }
        if is_marker(marker) {
            let rest = line[pos + 1..].trim();
            return if rest.is_empty() { None } else { Some(rest) };
        }
    }
    None
}

/// Is `marker` (no trailing space) an input prompt?
fn is_marker(marker: &str) -> bool {
    let Some(last) = marker.chars().last() else {
        return false;
    };
    if !PROMPT_CHARS.contains(&last) {
        return false;
    }
    let mut chars = marker.chars().rev();
    chars.next();
    if let Some(prev) = chars.next() {
        if matches!(prev, '-' | '=' | '<') {
            return false;
        }
    }
    // A plain word plus the prompt char ("items>") is not a prompt; real
    // prompts contain `@`, `:`, `/`, `~`, brackets, or are a bare symbol.
    let body: String = marker.chars().take(marker.chars().count() - 1).collect();
    // ">>" is shell append/heredoc syntax caught mid-line by a wrap, never a
    // prompt; ">>>" (Python) and ">" (older Claude Code) are.
    if marker == ">>" {
        return false;
    }
    let bare = body.is_empty() || body.chars().all(|c| PROMPT_CHARS.contains(&c));
    // Markers ending in `>`-like characters are only ever bare ("❯", ">",
    // ">>>"): anything longer is a redirect/heredoc/arrow caught mid-line
    // ("cat >> file", "Bash(cd dir; cat >>"). Shell prompts end in $ # %.
    if matches!(last, '>' | '❯' | '»') {
        return bare;
    }
    let shell_like = body.contains(['@', ':', '/', '~', '(', ')', '[', ']']);
    bare || shell_like
}

/// Whitespace-insensitive comparison key: the console hard-wraps long
/// questions, so a stored question and its echo differ only in line breaks.
pub fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Spinner glyphs Claude Code / similar TUIs animate while working.
const SPINNER: [char; 8] = ['*', '✻', '✶', '✳', '✢', '✽', '·', '⠋'];

/// Lines that are never part of an answer.
pub fn is_chrome(line: &str) -> bool {
    let c = core(line);
    if c.is_empty() {
        return true;
    }
    let lower = c.to_ascii_lowercase();
    // Help / status hints.
    if (c.starts_with('?') && lower.contains("shortcuts"))
        || c.starts_with("⏵⏵")
        || c.starts_with('⏸')
        || lower.contains("esc to interrupt")
        || lower.contains("ctrl+o to expand")
        || lower.starts_with("⎿  tip:")
        || lower.starts_with("tip:")
    {
        return true;
    }
    // Claude Code turn footer ("✻ Sautéed for 4m 13s · done 4:49 PM") and
    // spinner lines ("* Moonwalking… (1m 15s · ↓ 4.2k tokens)").
    if let Some(first) = c.chars().next() {
        if SPINNER.contains(&first) && (lower.contains("· done") || c.contains('…')) {
            return true;
        }
    }
    // A bare prompt with nothing typed.
    let bare_prompt = c.chars().count() <= 60
        && !c.contains(' ')
        && c.chars()
            .last()
            .map(|l| PROMPT_CHARS.contains(&l))
            .unwrap_or(false);
    if bare_prompt {
        return true;
    }
    false
}

/// Continuation of a multi-line user entry: Claude Code indents wrapped
/// question lines by two spaces; REPLs use `... `; bash PS2 is `> `.
pub fn user_continuation(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("... ") {
        return Some(rest.trim_end());
    }
    if line.trim_end() == "..." {
        return Some("");
    }
    if let Some(rest) = line.strip_prefix("  ") {
        if !rest.starts_with(' ') && !is_chrome(rest) && prompt_input(rest).is_none() {
            return Some(rest.trim_end());
        }
    }
    None
}

/// Parse a capture into turns, in order. Output lines before the first
/// prompt are dropped (they belong to no question).
pub fn parse(text: &str) -> Vec<Turn> {
    let mut turns: Vec<Turn> = Vec::new();
    let mut cur: Option<(String, Vec<String>)> = None;
    let mut in_user = false;

    for raw in text.lines() {
        let line = raw.trim_end();
        // A prompt line that is really chrome (Claude Code's collapsed
        // "❯ dep…o+18 lines (ctrl+o to expand)") is skipped entirely.
        let collapsed = line.to_ascii_lowercase().contains("ctrl+o to expand");
        if let Some(input) = prompt_input(line).filter(|_| !collapsed) {
            if let Some((u, a)) = cur.take() {
                turns.push(Turn {
                    user: u,
                    assistant: finish_assistant(a),
                });
            }
            cur = Some((input.to_string(), Vec::new()));
            in_user = true;
            continue;
        }
        let Some((user, answer)) = cur.as_mut() else {
            continue;
        };
        if in_user {
            if let Some(more) = user_continuation(line) {
                if !more.is_empty() {
                    user.push('\n');
                    user.push_str(more);
                }
                continue;
            }
            in_user = false;
        }
        if is_chrome(line) && answer.is_empty() {
            continue;
        }
        answer.push(line.to_string());
    }
    if let Some((u, a)) = cur.take() {
        turns.push(Turn {
            user: u,
            assistant: finish_assistant(a),
        });
    }
    turns.retain(|t| !t.user.trim().is_empty());
    // A TUI that re-renders its transcript (resize, scroll) leaves the same
    // turn several times in scrollback, each copy a longer render of the
    // same answer. Keep one, the most complete.
    let mut merged: Vec<Turn> = Vec::with_capacity(turns.len());
    for t in turns {
        if let Some(prev) = merged.last_mut() {
            if norm(&prev.user) == norm(&t.user) {
                let (a, b) = (norm(&prev.assistant), norm(&t.assistant));
                let same_render = a.is_empty()
                    || b.is_empty()
                    || a.starts_with(&b)
                    || b.starts_with(&a)
                    || prefix_len(&a, &b) >= 40;
                if same_render {
                    if t.assistant.len() > prev.assistant.len() {
                        *prev = t;
                    }
                    continue;
                }
            }
        }
        merged.push(t);
    }
    merged
}

fn prefix_len(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Tidy answer lines: drop chrome, trim blank edges, collapse blank runs.
pub fn clean_answer<'a>(lines: impl IntoIterator<Item = &'a str>) -> String {
    finish_assistant(
        lines
            .into_iter()
            .map(|l| l.trim_end().to_string())
            .collect(),
    )
}

fn finish_assistant(lines: Vec<String>) -> String {
    let mut lines: Vec<String> = lines
        .into_iter()
        .filter(|l| {
            // Keep blank lines inside the body, drop chrome anywhere.
            l.trim().is_empty() || !is_chrome(l)
        })
        .collect();
    while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.pop();
    }
    while lines.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.remove(0);
    }
    // Collapse runs of blank lines to one.
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for l in lines {
        if l.trim().is_empty() && out.last().map(|p| p.trim().is_empty()).unwrap_or(false) {
            continue;
        }
        out.push(l);
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_input_shapes() {
        assert_eq!(
            prompt_input("shafqat@Annihilator:~/git$ ls -la"),
            Some("ls -la")
        );
        assert_eq!(prompt_input("$ echo hi"), Some("echo hi"));
        assert_eq!(prompt_input("# whoami"), Some("whoami"));
        assert_eq!(prompt_input("❯ what is 2+2"), Some("what is 2+2"));
        assert_eq!(
            prompt_input("> older claude prompt"),
            Some("older claude prompt")
        );
        assert_eq!(prompt_input(">>> print(1)"), Some("print(1)"));
        assert_eq!(prompt_input("(venv) user@h:~$ pip list"), Some("pip list"));
        assert_eq!(prompt_input("$ "), None, "bare prompt is not a turn");
        assert_eq!(prompt_input("-> some arrow"), None);
        assert_eq!(prompt_input("=> value"), None);
        assert_eq!(prompt_input("items> 3"), None, "plain word is not a marker");
        assert_eq!(prompt_input("total 42"), None);
        assert_eq!(prompt_input("⏺ answer text"), None);
        assert_eq!(prompt_input("❯ is 5 > 3 ?"), Some("is 5 > 3 ?"));
        assert_eq!(
            prompt_input(">> crates/server/src/util.rs <<'EOF'"),
            None,
            "append artefact"
        );
        assert_eq!(prompt_input(">>> import os"), Some("import os"));
        assert_eq!(
            prompt_input("● Bash(cd /home/x/git; cat >> crates/server/src/util.rs <<'EOF'…)"),
            None,
            "redirect inside a tool line is not a prompt"
        );
        assert_eq!(
            prompt_input("user@host:~/dir> cmd"),
            None,
            "'>' prompts must be bare"
        );
        assert_eq!(prompt_input("  indented $ not a prompt"), None);
    }

    #[test]
    fn chrome_lines() {
        assert!(is_chrome("──────────────"));
        assert!(is_chrome("❯ "));
        assert!(is_chrome("  ? for shortcuts"));
        assert!(is_chrome("✻ Sautéed for 4m 13s · done 4:49 PM"));
        assert!(is_chrome("* Moonwalking… (1m 15s · ↓ 4.2k tokens)"));
        assert!(is_chrome("  ⎿  Tip: Share Claude Code and earn $10"));
        assert!(is_chrome("     … +14 lines (ctrl+o to expand)"));
        assert!(!is_chrome("⏺ Hi! Everything from earlier is live on prod"));
        assert!(!is_chrome("row 1"));
        assert!(!is_chrome("  What can I do for you?"));
    }

    #[test]
    fn parse_shell_session() {
        let text = "\
Last login: today
shafqat@host:~$ echo one
one
shafqat@host:~$ ls
Cargo.toml  src
shafqat@host:~$
";
        let turns = parse(text);
        assert_eq!(
            turns,
            vec![
                Turn {
                    user: "echo one".into(),
                    assistant: "one".into()
                },
                Turn {
                    user: "ls".into(),
                    assistant: "Cargo.toml  src".into()
                },
            ]
        );
    }

    #[test]
    fn parse_claude_code_transcript() {
        let text = "\
❯ Hi

⏺ Hi! Everything from earlier is live on prod — the chat API and the /remote client.

  The work is still uncommitted in the working tree. What would you like next?

✻ Worked for 3s · done 4:57 PM

❯ Mobile version is only showing the chats that have already been done it should take whatever is in
  chat

⏺ I'll make /remote mirror what's already on the console.

⏺ Bash(tmux display-message …)
  ⎿  1198 2000 44
     … +14 lines (ctrl+o to expand)

* Moonwalking… (1m 15s · ↓ 4.2k tokens)
  ⎿  Tip: Share Claude Code and earn $10 in usage credits · /passes

────────────────────────────────────
❯
────────────────────────────────────
  ? for shortcuts
";
        let turns = parse(text);
        assert_eq!(turns.len(), 2, "{turns:#?}");
        assert_eq!(turns[0].user, "Hi");
        assert_eq!(
            turns[0].assistant,
            "⏺ Hi! Everything from earlier is live on prod — the chat API and the /remote client.\n\n  The work is still uncommitted in the working tree. What would you like next?"
        );
        assert_eq!(
            turns[1].user,
            "Mobile version is only showing the chats that have already been done it should take whatever is in\nchat"
        );
        assert!(turns[1].assistant.starts_with("⏺ I'll make /remote mirror"));
        assert!(turns[1]
            .assistant
            .contains("⏺ Bash(tmux display-message …)\n  ⎿  1198 2000 44"));
        assert!(
            !turns[1].assistant.contains("Moonwalking"),
            "spinner is chrome"
        );
        assert!(!turns[1].assistant.contains("Tip:"), "tips are chrome");
        assert!(!turns[1].assistant.contains("────"), "frames are chrome");
        assert!(
            !turns[1].assistant.contains("ctrl+o"),
            "expand hints are chrome"
        );
    }

    #[test]
    fn parse_merges_rerendered_duplicate_turns_and_skips_collapsed_prompt() {
        let text = "\
❯ dep…o+18 lines (ctrl+o to expand)
  ⎿  Shell cwd was reset
❯ deploy

⏺ Before touching prod I need to know

❯ deploy

⏺ Before touching prod I need to know whether a restart

  will kill live tmux sessions.

❯ deploy

⏺ Before touching prod I need to know whether a restart
  will kill live tmux sessions. Checking the installed units.
";
        let turns = parse(text);
        assert_eq!(turns.len(), 1, "{turns:#?}");
        assert_eq!(turns[0].user, "deploy");
        assert!(turns[0].assistant.contains("Checking the installed units"));
    }

    #[test]
    fn parse_keeps_genuine_repeated_commands() {
        let text = "$ ls\na\n$ ls\nb\n$ \n";
        let turns = parse(text);
        assert_eq!(turns.len(), 2, "different outputs are different turns");
    }

    #[test]
    fn norm_collapses_wrapping() {
        assert_eq!(
            norm("Mobile version is only\n  showing the chats"),
            "Mobile version is only showing the chats"
        );
    }

    #[test]
    fn parse_python_repl_block() {
        let text = ">>> for i in range(2):\n...     print(i)\n... \n0\n1\n>>> \n";
        let turns = parse(text);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].user, "for i in range(2):\n    print(i)");
        assert_eq!(turns[0].assistant, "0\n1");
    }

    #[test]
    fn parse_drops_preamble_and_empty_turn_without_answer_is_kept() {
        let text = "motd banner\nno prompt here\n$ true\n$ echo x\nx\n";
        let turns = parse(text);
        assert_eq!(turns.len(), 2);
        assert_eq!(
            turns[0],
            Turn {
                user: "true".into(),
                assistant: String::new()
            }
        );
        assert_eq!(turns[1].assistant, "x");
    }
}
