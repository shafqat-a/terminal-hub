//! Line-oriented tmux control-mode protocol decoder.

use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    CommandOk { body: String },
    CommandErr { body: String },
    PaneOutput { pane: String, raw: String },
    Unknown(String),
}

#[derive(Default)]
pub struct Decoder {
    state: State,
    pending: Vec<String>,
}

#[derive(Default, Debug)]
enum State {
    #[default]
    Idle,
    InBlock,
}

impl Decoder {
    pub fn push_line(&mut self, line: &str) -> VecDeque<Event> {
        let mut out = VecDeque::new();
        match &self.state {
            State::Idle => {
                if line.starts_with("%begin") {
                    self.pending.clear();
                    self.state = State::InBlock;
                } else if let Some(rest) = line.strip_prefix("%output ") {
                    if let Some((pane, raw)) = rest.split_once(' ') {
                        out.push_back(Event::PaneOutput {
                            pane: pane.to_string(),
                            raw: raw.to_string(),
                        });
                    } else {
                        out.push_back(Event::Unknown(line.to_string()));
                    }
                } else {
                    out.push_back(Event::Unknown(line.to_string()));
                }
            }
            State::InBlock => {
                if line.starts_with("%end") || line.starts_with("%error") {
                    let err = line.starts_with("%error");
                    let body = std::mem::take(&mut self.pending).join("\n");
                    self.state = State::Idle;
                    out.push_back(if err {
                        Event::CommandErr { body }
                    } else {
                        Event::CommandOk { body }
                    });
                } else {
                    self.pending.push(line.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_command_ok_block() {
        let mut d = Decoder::default();
        assert!(d.push_line("%begin 1234 1 1").is_empty());
        assert!(d.push_line("session-one").is_empty());
        assert!(d.push_line("session-two").is_empty());
        let ev = d.push_line("%end 1234 1 1");
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::CommandOk { body: "session-one\nsession-two".to_string() }
        );
    }

    #[test]
    fn decodes_a_command_err_block() {
        let mut d = Decoder::default();
        d.push_line("%begin 1 1 1");
        d.push_line("no such session");
        let ev = d.push_line("%error 1 1 1");
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::CommandErr { body: "no such session".to_string() }
        );
    }

    #[test]
    fn decodes_a_pane_output_line() {
        let mut d = Decoder::default();
        let ev = d.push_line("%output %0 hello\\r\\n");
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::PaneOutput { pane: "%0".to_string(), raw: "hello\\r\\n".to_string() }
        );
    }
}
