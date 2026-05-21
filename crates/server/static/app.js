const term = new Terminal({ cursorBlink: true, fontFamily: "Menlo, monospace", fontSize: 13 });
term.open(document.getElementById("terminal"));
term.writeln("terminal-hub M1 walking skeleton — connecting…");
