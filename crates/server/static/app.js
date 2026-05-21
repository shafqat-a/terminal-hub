const term = new Terminal({
  cursorBlink: true,
  fontFamily: "Menlo, monospace",
  fontSize: 13,
  scrollback: 5000,
});
term.open(document.getElementById("terminal"));
term.writeln("terminal-hub M1 — connecting…");

const proto = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${proto}://${location.host}/ws/attach`);
ws.binaryType = "arraybuffer";

ws.addEventListener("open", () => {
  term.writeln("\x1b[32mconnected\x1b[0m");
});
ws.addEventListener("message", (ev) => {
  if (ev.data instanceof ArrayBuffer) {
    term.write(new Uint8Array(ev.data));
  } else {
    term.write(ev.data);
  }
});
ws.addEventListener("close", () => {
  term.writeln("\r\n\x1b[31mdisconnected\x1b[0m");
});

term.onData((data) => {
  if (ws.readyState === WebSocket.OPEN) ws.send(data);
});
