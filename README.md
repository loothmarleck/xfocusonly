# xfocusonly

**Any app you run on Linux can log every key you type and read everything you
copy. No permission prompt, no trace.** The `demo.c` in this repo does it in
130 lines.

xfocusonly stops that. Your keystrokes go only to the window you are typing
in. Only that window can read your clipboard. Everything else gets nothing.

It is the normal Xorg server plus one file. Same `startx`, same drivers, same
apps.

## Install

Clone this repo, then:

    ./build

That fetches xorg-server, adds xfocusonly, compiles, and prints the path of
the finished `Xorg` binary. If a build tool is missing, the script names it.

Install that binary the way your distro expects, e.g.

    sudo ninja -C xorg/build install

Keep a copy of your old `Xorg` binary first. If anything goes wrong, putting
it back is your way out.

## Set it up

Copy the config in and add your window manager, one path per line:

    sudo cp xfocusonly.conf /etc/X11/xfocusonly.conf

    /usr/bin/dwm

(`which dwm` tells you the path.) Start X the way you always do. That's it.

## See it work

    ./build demo
    ./demo

That's the keylogger. Type in another window, copy something.

- Normal Xorg: it prints everything.
- xfocusonly: it prints nothing, and your X log gets one line.

      xfocusonly deny client=3 pid=1234 exe=/home/you/xfocusonly/demo reason=xi2-raw-key-event

## Something stopped working

A few programs genuinely need keys while unfocused. Check your X log
(`~/.local/share/xorg/Xorg.0.log` or `/var/log/Xorg.0.log`) for
`xfocusonly deny` — each line names the program that got blocked. If you trust
it, add its path to the config. Usual suspects:

- hotkey daemons — `sxhkd`
- input methods — `fcitx5`, `ibus`
- clipboard managers

Anything in that file is trusted completely, so keep the list short.

## What it does and doesn't

| | Xorg | xfocusonly |
|---|---|---|
| Keys reach the focused window | yes | yes |
| Any other app can read them too | yes | **no** |
| The focused app can read the clipboard | yes | yes |
| A background app can read the clipboard | yes | **no** |
| WM hotkeys, dmenu, lockers, menus, games | yes | yes |

It protects **keystrokes and the clipboard**. It does not stop apps from
reading other windows' pixels, tracking your mouse, or faking input. Those are
different problems and this does not solve them.

Every check runs through X-ACE, Xorg's own access-control layer, so the patch
to Xorg itself is one line of logic; the rest is build glue. The exact rules,
each with the test that proves it, are at the top of `xfocusonly.c`.

## What's in here

    xfocusonly.c       the module — one file, ~530 lines
    xfocusonly.conf    default config
    xorg.patch         makes xorg-server build and start the module
    build              fetch xorg-server, add the module, compile
    tests.py           11 tests: each proves one leak is closed and one normal use still works
    demo.c             the keylogger

## Maintaining it

Rules, in order of importance:

1. **Keep it this simple.** One idea: only the focused window gets input,
   your WM is the exception. If a change makes this README longer, it's
   probably the wrong change. Say no to features. Say no to packaging.
2. **`./build test` must pass before every commit.** 11/11, no exceptions.
   Needs `python3` and `python-xcffib`; it runs a headless Xvfb built from the
   same tree.
3. **Every rule has a test.** Add a rule to `xfocusonly.c`, add a test to
   `tests.py`, and list it in the `RULES` table at the top of `xfocusonly.c`.
   No rule without a test, no test without a rule.
4. **New Xorg release?** Change `XORG_VERSION` in `build`, run `./build test`,
   commit. The 21.1 branch only takes security fixes, so the hook points
   don't move.
5. **Don't touch `xorg/`.** It's a fetched checkout, ignored by git. `build`
   resets it every time.

## License

MIT for xfocusonly, its tests and its scripts. Xorg's own license applies to
Xorg.
