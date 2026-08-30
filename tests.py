#!/usr/bin/env python3
"""xfocusonly test suite. Run with ./build test (or python3 tests.py [-v] [name...]).

Every test starts a fresh Xvfb built from xorg/ and plays three roles:
  victim     an ordinary client owning the focused window (must get keys)
  attacker   an ordinary client owning nothing relevant (must get nothing)
  injector   fakes hardware input via XTEST
plus a privileged client where needed, run from a copy of the python binary
so it has its own executable path to list in the config.
Needs python-xcffib."""
import importlib, os, shutil, subprocess, sys, textwrap, time, pathlib, traceback

import xcffib, xcffib.xproto as xp, xcffib.xtest, xcffib.xinput as xi, xcffib.record as rec

ROOT = pathlib.Path(__file__).resolve().parent
XVFB = ROOT / "xorg" / "build" / "hw" / "vfb" / "Xvfb"
LOGDIR = ROOT / "xorg" / "build" / "test-logs"
# Privilege is granted by executable path. All test clients are python, so a
# privileged client must run from a *different* binary: a copy of python3.
PRIV_PYTHON = ROOT / "xorg" / "build" / "test-bin" / "xfocusonly-priv-python3"


def _free_display(start=70):
    for n in range(start, start + 100):
        if not os.path.exists(f"/tmp/.X11-unix/X{n}") and not os.path.exists(f"/tmp/.X{n}-lock"):
            return n
    raise RuntimeError("no free display")


class Server:
    def __init__(self, name, extra_args=()):
        self.name = name
        self.display = _free_display()
        LOGDIR.mkdir(parents=True, exist_ok=True)
        self.log = open(LOGDIR / f"{name}.log", "w")
        env = dict(os.environ)
        # Only PRIV_PYTHON is privileged for this server.
        if not PRIV_PYTHON.exists():
            PRIV_PYTHON.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sys.executable, PRIV_PYTHON)
        conf = LOGDIR / f"{name}.xfocusonly.conf"
        conf.write_text(f"{PRIV_PYTHON}\n")
        env["XFOCUSONLY_CONF"] = str(conf)
        self.proc = subprocess.Popen(
            [str(XVFB), f":{self.display}", "-nolisten", "tcp", "-screen", "0", "640x480x24", *extra_args],
            stdout=self.log, stderr=subprocess.STDOUT, env=env)
        self._wait_socket()
        self.conns = []

    def _wait_socket(self):
        path = f"/tmp/.X11-unix/X{self.display}"
        for _ in range(100):
            if os.path.exists(path):
                return
            if self.proc.poll() is not None:
                raise RuntimeError(f"Xvfb exited early, see {self.log.name}")
            time.sleep(0.05)
        raise RuntimeError("Xvfb socket never appeared")

    def connect(self):
        c = xcffib.connect(display=f":{self.display}")
        self.conns.append(c)
        return c

    def privileged(self, code, timeout=10):
        """Run `code` in a privileged client process against this server.
        The code may `from tests import *`; its stdout is returned."""
        env = dict(os.environ, DISPLAY=f":{self.display}", PYTHONHOME="/usr",
                   PYTHONPATH=str(ROOT))
        r = subprocess.run([str(PRIV_PYTHON), "-c", textwrap.dedent(code)],
                           env=env, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise AssertionError(f"privileged client failed:\n{r.stderr}")
        return r.stdout

    def xfocusonly_log(self):
        self.log.flush()
        return [l for l in open(self.log.name) if "xfocusonly" in l]

    def close(self):
        for c in self.conns:
            try: c.disconnect()
            except Exception: pass
        self.proc.terminate()
        try: self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired: self.proc.kill()
        self.log.close()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---- helpers used by tests --------------------------------------------------

def root(conn):
    return conn.get_setup().roots[0].root


def make_window(conn, event_mask=xp.EventMask.KeyPress | xp.EventMask.KeyRelease | xp.EventMask.FocusChange):
    """Create and map a small window owned by `conn`."""
    scr = conn.get_setup().roots[0]
    wid = conn.generate_id()
    conn.core.CreateWindow(scr.root_depth, wid, scr.root, 0, 0, 100, 100, 0,
                           xp.WindowClass.InputOutput, scr.root_visual,
                           xp.CW.EventMask, [event_mask])
    conn.core.MapWindow(wid)
    conn.flush()
    return wid


def give_focus(conn, wid):
    conn.core.SetInputFocus(xp.InputFocus.PointerRoot, wid, xp.Time.CurrentTime)
    conn.flush()
    conn.core.GetInputFocus().reply()   # round trip so it's applied


def inject_key(conn, keycode=38, press=True):
    """Fake a hardware key event via XTEST (keycode 38 = 'a' on pc105)."""
    xt = conn(xcffib.xtest.key)
    t = 2 if press else 3   # KeyPress / KeyRelease event type codes
    xt.FakeInput(t, keycode, xp.Time.CurrentTime, root(conn), 0, 0, 0)
    conn.flush()


def drain(conn, wait=0.3):
    """Collect all pending events on conn after a short wait."""
    conn.flush()
    time.sleep(wait)
    out = []
    while True:
        ev = conn.poll_for_event()
        if ev is None:
            break
        out.append(ev)
    return out


def key_events(events):
    return [e for e in events if isinstance(e, (xp.KeyPressEvent, xp.KeyReleaseEvent))]


def atom(conn, name):
    return conn.core.InternAtom(False, len(name), name).reply().atom


def check(cookie):
    """True if a checked request succeeded, False on an X error."""
    try:
        cookie.check(); return True
    except xcffib.Error:
        return False

# --- keylog_root --------------------------------------------
# Attacker selects KeyPress on the root window. Key events for the focused
# window propagate up the tree, so on an unprotected server the attacker sees
# every keystroke. Expected: victim gets the key, attacker gets nothing.
def test_keylog_root(srv):
    victim, attacker, injector = srv.connect(), srv.connect(), srv.connect()

    w = make_window(victim)
    give_focus(victim, w)

    attacker.core.ChangeWindowAttributes(root(attacker), xp.CW.EventMask,
                                         [xp.EventMask.KeyPress | xp.EventMask.KeyRelease])
    attacker.flush()

    inject_key(injector, press=True)
    inject_key(injector, press=False)

    got_victim = key_events(drain(victim))
    got_attacker = key_events(drain(attacker))

    assert got_victim, "victim (focus owner) did not receive the key event"
    assert not got_attacker, f"attacker received {len(got_attacker)} key events via root window"

# --- keylog_root_pointerroot --------------------------------
# Focus is PointerRoot (some window managers use this). Key events then go to
# the window under the pointer and propagate up to root, where the attacker is
# listening. Must get nothing. (With focus on a real window, X already stops
# propagation at the focus window, so root listeners get nothing regardless.)
def test_keylog_root_pointerroot(srv):
    victim, attacker, injector = srv.connect(), srv.connect(), srv.connect()

    make_window(victim, event_mask=xp.EventMask.FocusChange)
    victim.core.SetInputFocus(xp.InputFocus.PointerRoot, xp.InputFocus.PointerRoot, xp.Time.CurrentTime)
    victim.flush()

    attacker.core.ChangeWindowAttributes(root(attacker), xp.CW.EventMask,
                                         [xp.EventMask.KeyPress | xp.EventMask.KeyRelease])
    attacker.flush()

    inject_key(injector, press=True)
    inject_key(injector, press=False)

    got_attacker = key_events(drain(attacker))
    assert not got_attacker, f"attacker received {len(got_attacker)} key events via root window"

# --- keylog_xi2raw ------------------------------------------
# Attacker selects XI_RawKeyPress/Release on root via XInput2. Raw events are
# delivered regardless of focus - the standard modern keylogger. Must get nothing.
XI_RawKeyPress, XI_RawKeyRelease = 13, 14
XIAllMasterDevices = 1

def select_raw_keys(conn, window):
    bits = (1 << XI_RawKeyPress) | (1 << XI_RawKeyRelease)
    mask = xi.EventMask.synthetic(deviceid=XIAllMasterDevices, mask_len=1, mask=[bits])
    ext = conn(xi.key)
    ext.XIQueryVersion(2, 0).reply()
    ext.XISelectEvents(window, 1, [mask])
    conn.flush()

def raw_key_events(events):
    return [e for e in events if isinstance(e, (xi.RawKeyPressEvent, xi.RawKeyReleaseEvent))]

def test_keylog_xi2raw(srv):
    victim, attacker, injector = srv.connect(), srv.connect(), srv.connect()
    w = make_window(victim)
    give_focus(victim, w)

    select_raw_keys(attacker, root(attacker))

    inject_key(injector, press=True)
    inject_key(injector, press=False)

    assert key_events(drain(victim)), "victim (focus owner) did not receive the key event"
    got = raw_key_events(drain(attacker))
    assert not got, f"attacker received {len(got)} XI2 raw key events"

# --- querykeymap --------------------------------------------
# Attacker polls QueryKeymap while a key is held. The keymap is a bit vector of
# all 256 keycodes; polling it fast reconstructs typing. Must read as all-zero.
KEYCODE = 38

def test_querykeymap(srv):
    victim, attacker, injector = srv.connect(), srv.connect(), srv.connect()
    w = make_window(victim)
    give_focus(victim, w)

    inject_key(injector, KEYCODE, press=True)
    drain(injector)
    try:
        keys = attacker.core.QueryKeymap().reply().keys
        pressed = [i for i in range(256) if keys[i // 8] & (1 << (i % 8))]
    finally:
        inject_key(injector, KEYCODE, press=False)

    assert KEYCODE not in pressed, f"attacker saw keycode {KEYCODE} held via QueryKeymap"

# --- record -------------------------------------------------
# Attacker uses the RECORD extension to tap all device events. Must fail:
# either the extension is not present for it, or enabling the context errors.
def test_record(srv):
    victim, attacker, injector = srv.connect(), srv.connect(), srv.connect()
    w = make_window(victim)
    give_focus(victim, w)

    q = attacker.core.QueryExtension(len("RECORD"), "RECORD").reply()
    if not q.present:
        return  # hidden from unprivileged clients: acceptable outcome

    ext = attacker(rec.key)
    ctx = attacker.generate_id()
    r = rec.Range.synthetic(
        core_requests=rec.Range8.synthetic(0, 0), core_replies=rec.Range8.synthetic(0, 0),
        ext_requests=rec.ExtRange.synthetic(rec.Range8.synthetic(0, 0), rec.Range16.synthetic(0, 0)),
        ext_replies=rec.ExtRange.synthetic(rec.Range8.synthetic(0, 0), rec.Range16.synthetic(0, 0)),
        delivered_events=rec.Range8.synthetic(0, 0),
        device_events=rec.Range8.synthetic(2, 3),   # KeyPress..KeyRelease
        errors=rec.Range8.synthetic(0, 0), client_started=False, client_died=False)
    XRecordAllClients = 3
    try:
        ext.CreateContext(ctx, 0, 1, 1, [XRecordAllClients], [r], is_checked=True).check()
    except xcffib.Error:
        return  # refused: acceptable
    # Data from the tap arrives as a reply stream; we only need to know whether
    # enabling is allowed, since an enabled context sees every keystroke.
    tap = attacker(rec.key)
    try:
        # EnableContext replies indefinitely; use a separate connection for the tap
        # and just check the *first* reply arrives after a key event.
        cookie = tap.EnableContext(ctx)
        inject_key(injector, press=True); inject_key(injector, press=False)
        drain(injector)
        cookie.reply()
    except xcffib.Error:
        return  # refused: acceptable
    raise AssertionError("attacker successfully enabled a RECORD context tapping key events")

# --- grabs --------------------------------------------------
# Passive key grabs: allowed on your own window, refused on root/foreign
# windows (that is the window manager's privilege). Active GrabKeyboard is
# allowed for anyone: it diverts input visibly rather than copying it.
def test_grabs(srv):
    app = srv.connect()
    w = make_window(app)
    give_focus(app, w)

    own = app.core.GrabKeyChecked(False, w, xp.ModMask.Any, 38, xp.GrabMode.Async, xp.GrabMode.Async)
    assert check(own), "GrabKey on own window was refused"

    foreign = app.core.GrabKeyChecked(False, root(app), xp.ModMask.Any, 38, xp.GrabMode.Async, xp.GrabMode.Async)
    assert not check(foreign), "GrabKey on root window was allowed for an unprivileged client"

    active = app.core.GrabKeyboard(False, w, xp.Time.CurrentTime, xp.GrabMode.Async, xp.GrabMode.Async).reply()
    assert active.status == xp.GrabStatus.Success, "active GrabKeyboard was refused"

    # a client holding an active keyboard grab must receive the keys
    inject_key(app, press=True); inject_key(app, press=False)
    assert key_events(drain(app)), "grabbing client did not receive key events"
    app.core.UngrabKeyboard(xp.Time.CurrentTime); app.flush()

# --- replay -------------------------------------------------
# Sync keyboard grab + AllowEvents(ReplayKeyboard) lets a client see every key
# and then hand it on to the real target: a covert keylogger. ReplayKeyboard is
# privileged-only; the other AllowEvents modes stay available.
def test_replay(srv):
    app = srv.connect()
    w = make_window(app)
    give_focus(app, w)
    r = app.core.GrabKeyboard(False, w, xp.Time.CurrentTime, xp.GrabMode.Async, xp.GrabMode.Sync).reply()
    assert r.status == xp.GrabStatus.Success

    assert check(app.core.AllowEventsChecked(xp.Allow.AsyncKeyboard, xp.Time.CurrentTime)), \
        "AllowEvents(AsyncKeyboard) refused"
    assert not check(app.core.AllowEventsChecked(xp.Allow.ReplayKeyboard, xp.Time.CurrentTime)), \
        "AllowEvents(ReplayKeyboard) allowed for an unprivileged client"

    out = srv.privileged('''
        import xcffib, xcffib.xproto as xp
        from tests import *
        c = xcffib.connect(); w = make_window(c); give_focus(c, w)
        c.core.GrabKeyboard(False, w, xp.Time.CurrentTime, xp.GrabMode.Async, xp.GrabMode.Sync).reply()
        try:
            c.core.AllowEventsChecked(xp.Allow.ReplayKeyboard, xp.Time.CurrentTime).check(); print("replay ok")
        except xcffib.Error: print("replay refused")
    ''')
    assert "replay ok" in out, f"privileged ReplayKeyboard refused: {out!r}"

# --- clipboard ----------------------------------------------
# Victim owns focus and the CLIPBOARD selection. Attacker (never focused) asks
# to convert it. The attacker must see an empty result (SelectionNotify with
# property None) and the victim must never receive a SelectionRequest.
def test_clipboard(srv):
    victim, attacker = srv.connect(), srv.connect()
    CLIPBOARD = atom(victim, "CLIPBOARD")
    UTF8 = atom(victim, "UTF8_STRING")

    w = make_window(victim, event_mask=xp.EventMask.FocusChange)
    give_focus(victim, w)
    victim.core.SetSelectionOwner(w, CLIPBOARD, xp.Time.CurrentTime)
    victim.flush()
    assert victim.core.GetSelectionOwner(CLIPBOARD).reply().owner == w

    aw = make_window(attacker, event_mask=0)
    prop = atom(attacker, "XFOCUSONLY_TEST")
    attacker.core.ConvertSelection(aw, CLIPBOARD, UTF8, prop, xp.Time.CurrentTime)
    attacker.flush()

    reqs = [e for e in drain(victim) if isinstance(e, xp.SelectionRequestEvent)]
    notes = [e for e in drain(attacker) if isinstance(e, xp.SelectionNotifyEvent)]

    assert not reqs, "victim received a SelectionRequest from an unfocused client"
    assert notes and notes[0].property == 0, "attacker did not get an empty SelectionNotify"

# --- legit_paste --------------------------------------------
# The legitimate path: a focused client converts a selection owned by another
# client and gets a real SelectionRequest -> data round trip. Also: a client
# that *just lost* focus can still paste (grace period).
def convert_ok(owner, requester, rw, sel, target, prop):
    requester.core.ConvertSelection(rw, sel, target, prop, xp.Time.CurrentTime)
    requester.flush()
    reqs = [e for e in drain(owner) if isinstance(e, xp.SelectionRequestEvent)]
    return bool(reqs)

def test_legit_paste(srv):
    owner, app = srv.connect(), srv.connect()
    CLIPBOARD, UTF8, PROP = atom(owner, "CLIPBOARD"), atom(owner, "UTF8_STRING"), atom(owner, "P")

    ow = make_window(owner)
    owner.core.SetSelectionOwner(ow, CLIPBOARD, xp.Time.CurrentTime); owner.flush()

    aw = make_window(app)
    give_focus(app, aw)
    assert convert_ok(owner, app, aw, CLIPBOARD, UTF8, PROP), "focused client could not read the clipboard"

    # focus moves away; app should still be able to finish a paste shortly after
    give_focus(owner, ow)
    assert convert_ok(owner, app, aw, CLIPBOARD, UTF8, PROP), "recently-focused client could not read the clipboard"


def test_legit_paste_child_process(srv):
    """A process descended from the focus owner's process (this test process)
    may read the clipboard, e.g. `xclip -o` run from the focused terminal."""
    import subprocess, sys, os, pathlib
    owner, app = srv.connect(), srv.connect()
    CLIPBOARD = atom(owner, "CLIPBOARD")
    ow = make_window(owner)
    owner.core.SetSelectionOwner(ow, CLIPBOARD, xp.Time.CurrentTime); owner.flush()
    aw = make_window(app)
    give_focus(app, aw)

    child = subprocess.Popen([sys.executable, "-c", """
import xcffib, xcffib.xproto as xp, time
from tests import *
c = xcffib.connect()
w = make_window(c, event_mask=0)
sel = c.core.InternAtom(False, 9, "CLIPBOARD").reply().atom
tgt = c.core.InternAtom(False, 11, "UTF8_STRING").reply().atom
c.core.ConvertSelection(w, sel, tgt, tgt, xp.Time.CurrentTime); c.flush(); time.sleep(0.5)
"""], env=dict(os.environ, DISPLAY=f":{srv.display}", PYTHONPATH=str(pathlib.Path(__file__).parent)))
    child.wait(timeout=10)
    reqs = [e for e in drain(owner, 0.2) if isinstance(e, xp.SelectionRequestEvent)]
    assert reqs, "child process of the focused client could not read the clipboard"

# --- privileged ---------------------------------------------
# A privileged client (allowlisted executable) keeps full X semantics:
# XI2 raw key events, RECORD visible, passive grab on root.
def test_privileged(srv):
    victim = srv.connect()
    w = make_window(victim)
    give_focus(victim, w)

    out = srv.privileged('''
        import xcffib, xcffib.xproto as xp, xcffib.xinput as xi
        from tests import *
        c = xcffib.connect()
        inj = xcffib.connect()
        select_raw_keys(c, root(c))
        inject_key(inj, press=True); inject_key(inj, press=False)
        print("raw", len(raw_key_events(drain(c))))
        print("record", c.core.QueryExtension(6, "RECORD").reply().present)
        try:
            c.core.GrabKeyChecked(False, root(c), xp.ModMask.Any, 38, xp.GrabMode.Async, xp.GrabMode.Async).check()
            print("rootgrab ok")
        except xcffib.Error:
            print("rootgrab refused")
    ''')
    assert "raw 2" in out, f"privileged client did not get raw key events: {out!r}"
    assert "record 1" in out, f"RECORD hidden from privileged client: {out!r}"
    assert "rootgrab ok" in out, f"root GrabKey refused for privileged client: {out!r}"


# --- runner ---------------------------------------------------------------

def main(argv):
    verbose = "-v" in argv
    want = [a for a in argv if a != "-v"]
    mod = sys.modules[__name__]
    names = [n for n in dir(mod) if n.startswith("test_") and callable(getattr(mod, n))]
    names.sort(key=lambda n: (n.split("_child")[0], n))
    if want:
        names = [n for n in names if any(w in n for w in want)]
    failed = 0
    for n in names:
        try:
            with Server(n) as srv:
                getattr(mod, n)(srv)
            print(f"PASS  {n}")
        except Exception as e:
            failed += 1
            msg = str(e).splitlines()[0] if str(e) else e.__class__.__name__
            print(f"FAIL  {n}: {msg}")
            if verbose:
                traceback.print_exc()
    print(f"\n{len(names) - failed}/{len(names)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
