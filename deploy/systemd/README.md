# Deploying Terminal Hub (systemd)

Terminal Hub is deployed as **two** systemd units:

| Unit | Owns | Purpose |
|------|------|---------|
| `terminal-hub-tmux.service` | the **tmux server** + all live sessions | Keeps sessions alive across app restarts |
| `terminal-hub.service`      | the **web app** (`/usr/local/bin/terminal-hub`) | Serves the UI; spawns tmux *clients* only |

## Why two units (read this before "simplifying" to one)

tmux keeps every session **in memory** — there is no on-disk persistence of
running processes. A session survives the app restarting only if the tmux
*server* process outlives it.

The app spawns its tmux server lazily. If that server lives in the app's own
systemd cgroup, then `systemctl restart terminal-hub` (i.e. every redeploy)
SIGKILLs it along with the app, because the default `KillMode=control-group`
kills the **entire cgroup**. Result: every redeploy silently destroyed all
running sessions.

The fix is to give the tmux server its own unit and cgroup:

- `terminal-hub-tmux.service` starts the server with a `_keeper` session
  (`sleep infinity`) plus `set-option -g exit-empty off`, so it never exits on
  its own, and uses `KillMode=none` so nothing tears it down.
- `terminal-hub.service` declares `Requires=`/`After=terminal-hub-tmux.service`,
  so the server is always up first. The app then only spawns tmux *clients*
  (in the app cgroup, disposable); the sessions themselves live in the tmux
  unit's cgroup and are untouched by an app restart.
- On startup the app re-adopts every live `aidc_*` tmux session, so sessions
  reappear in the UI automatically after a restart. The `_keeper` session has
  no `aidc_` prefix, so it is ignored by the app and never shown.

What this survives: app crash, app restart, and redeploy (new binary).
What it does **not** survive: a machine reboot or a tmux-server crash — those
lose the in-memory sessions, and nothing can preserve live processes across
them.

## Install

The unit files use placeholders. Substitute them for your host and install:

```sh
# 1. Pick your values.
USER_NAME=youruser
GROUP_NAME=youruser
HOME_DIR=/home/$USER_NAME
DATA_DIR=$HOME_DIR/.local/share/terminal-hub/sessions

# 2. Config (edit the password etc. after copying).
sudo install -m 600 -o root -g root deploy/systemd/terminal-hub.env.example /etc/terminal-hub.env
sudoedit /etc/terminal-hub.env        # set AI_CONDUCTOR_DATA_DIR=$DATA_DIR among others

# 3. Render and install the units.
for u in terminal-hub-tmux.service terminal-hub.service; do
  sed -e "s|__USER__|$USER_NAME|g" \
      -e "s|__GROUP__|$GROUP_NAME|g" \
      -e "s|__HOME__|$HOME_DIR|g" \
      -e "s|__DATA_DIR__|$DATA_DIR|g" \
      "deploy/systemd/$u" | sudo tee "/etc/systemd/system/$u" >/dev/null
done

# 4. Enable + start (tmux unit first; the dependency also enforces ordering).
sudo systemctl daemon-reload
sudo systemctl enable --now terminal-hub-tmux.service
sudo systemctl enable --now terminal-hub.service
```

> The `__DATA_DIR__` placeholder must match `AI_CONDUCTOR_DATA_DIR` in
> `/etc/terminal-hub.env`. The tmux socket is always `$DATA_DIR/tmux.sock`.

## Adopting an already-running tmux server

If the app was previously installed as a single unit, the tmux server (and
every live session) already exists inside `terminal-hub.service`'s cgroup.
Starting `terminal-hub-tmux.service` then only adds `_keeper` to that server;
its own cgroup stays empty and is removed, so the next app restart would still
kill everything. Move the live tree over once (cgroup v2, as root):

```sh
CG=/sys/fs/cgroup/system.slice/terminal-hub-tmux.service
APP=/sys/fs/cgroup/system.slice/terminal-hub.service
APP_PID=$(systemctl show -p MainPID --value terminal-hub.service)
sudo mkdir -p $CG
for p in $(cat $APP/cgroup.procs); do
  # keep the app and its own tmux *clients*; move the server + everything else
  [ "$p" = "$APP_PID" ] && continue
  [ "$(awk '/^PPid/{print $2}' /proc/$p/status)" = "$APP_PID" ] && continue
  echo $p | sudo tee $CG/cgroup.procs >/dev/null
done
cat /proc/$(tmux -S $DATA_DIR/tmux.sock display-message -p '#{pid}')/cgroup   # => terminal-hub-tmux.service
```

After that a redeploy is safe. (The keeper uses `new-session -A` so the tmux
unit is idempotent against a server that already has `_keeper`.)

## Build & redeploy a new binary

```sh
cargo build --release -p terminal-hub
sudo install -m 755 target/release/terminal-hub /usr/local/bin/terminal-hub
sudo systemctl restart terminal-hub.service   # sessions survive this
```

Do **not** restart `terminal-hub-tmux.service` as part of a redeploy — there is
no need to, and stopping it (even though `KillMode=none` keeps the server up)
is pointless churn. Only the app unit needs restarting for a new binary.

## Verify it works

```sh
# Both active, server holding the keeper session:
systemctl is-active terminal-hub-tmux.service terminal-hub.service
tmux -S "$DATA_DIR/tmux.sock" list-sessions      # shows _keeper (+ any aidc_*)

# The real test: a session must survive an app restart.
tmux -S "$DATA_DIR/tmux.sock" new-session -A -d -s aidc_probe -- /bin/bash
sudo systemctl restart terminal-hub.service
tmux -S "$DATA_DIR/tmux.sock" has-session -t aidc_probe && echo "SURVIVED"
tmux -S "$DATA_DIR/tmux.sock" kill-session -t aidc_probe   # cleanup
```

Confirm the tmux server sits in the **tmux** unit's cgroup, not the app's:

```sh
SRV=$(pgrep -f "tmux -S $DATA_DIR/tmux.sock")
cat /proc/$SRV/cgroup    # => .../terminal-hub-tmux.service
```
