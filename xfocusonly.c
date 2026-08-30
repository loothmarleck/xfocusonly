/* xfocusonly - only the focused window gets your keystrokes and clipboard.
 *
 * A small module for the X.Org server. It hooks the places where the server
 * hands events, device state and selections to clients, and applies a
 * handful of rules. See README.md for the big picture.
 *
 * IDENTITY
 *   A local client is identified when it connects: SO_PEERCRED -> pid ->
 *   /proc/<pid>/exe. A client is PRIVILEGED if that path is listed in
 *   /etc/X11/xfocusonly.conf (or $XFOCUSONLY_CONF), one absolute path per
 *   line. Privileged clients get plain X11 semantics. Put your window manager
 *   there and nothing else unless you know why. Remote (TCP) clients are
 *   never privileged.
 *
 *   The FOCUS OWNER is the client owning the window with keyboard focus (per
 *   master keyboard) or holding an active keyboard grab. Under PointerRoot
 *   focus it is the client owning the non-root window under the pointer.
 *
 * RULES                                                 hook            test
 *   1 Key events (core, XI1, XI2) are delivered only    receive         keylog_root*
 *     to the focus owner.
 *   2 XI2 raw key events: privileged only.              receive         keylog_xi2raw
 *   3 QueryKeymap / XI QueryDeviceState return an       device          querykeymap
 *     empty map unless focus owner or privileged.
 *   4 Passive key grabs only on the client's own        device          grabs
 *     windows unless privileged (root hotkeys are
 *     the window manager's business).
 *   5 AllowEvents(ReplayKeyboard): privileged only      device          replay
 *     (sync grab + replay is a covert keylogger).
 *   6 Active GrabKeyboard is allowed for everyone:      -               grabs
 *     it diverts input visibly.
 *   7 RECORD is invisible and undispatchable for        ext             record
 *     unprivileged clients.
 *   8 ConvertSelection succeeds for the focus owner,    selection       clipboard,
 *     a client focused within the last 5 s, a process                   legit_paste
 *     descended from the focus owner (xclip -o in the
 *     focused terminal), or privileged. Others get a
 *     SelectionNotify with property None, like an
 *     empty clipboard. The owner never sees the request.
 *
 *   Denies are logged once per client and reason:
 *     xfocusonly deny client=N pid=P exe=/path reason=<reason>
 *
 * ACCEPTED GAPS
 *   KeymapNotify on EnterNotify gives the window under the pointer a one-time
 *   snapshot of held keys. XTEST is untouched (it injects, it does not read).
 *   XkbGetState / XkbStateNotify / XkbGetIndicatorState leak modifier, lock
 *   and group state (Shift/Ctrl held, CapsLock, layout) but never which
 *   letter or digit key was pressed - a password's characters stay hidden.
 *   Gating them would blank the CapsLock and keyboard-layout indicators that
 *   status bars and IMEs read while unfocused, so they are left open.
 *   Pointer motion and position are readable by any client: xfocusonly
 *   protects keystrokes and the clipboard, not the mouse.
 *   Selection ownership changes are visible to all; contents are not. A
 *   privileged binary is trusted absolutely.
 *
 * Every hook is X-ACE, the server's built-in access-control layer, so
 * xfocusonly changes one line of server logic: the ReplayKeyboard check in
 * dix/events.c, which X-ACE does not cover. The rest of the patch is build
 * glue.
 *
 * MIT licensed. Everything else in the server is X.Org's.
 */
#include <dix-config.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <X11/Xproto.h>
#include <X11/extensions/XI2.h>
#include <X11/extensions/XIproto.h>
#include <X11/extensions/XI2proto.h>

#include "dixstruct.h"
#include "extinit.h"
#include "extnsionst.h"
#include "inputstr.h"
#include "os.h"
#include "privates.h"
#include "resource.h"
#include "windowstr.h"
#include "xace.h"
#include "xacestr.h"
#include "exglobals.h"

#define XFOCUSONLY_DEFAULT_CONF   "/etc/X11/xfocusonly.conf"
#define XFOCUSONLY_FOCUS_GRACE_MS 5000

Bool noXFocusOnlyExtension = FALSE;   /* -extension XFOCUSONLY turns it off */

struct XFocusOnlyClient {
    int pid;                    /* 0 if unknown (remote client) */
    char exe[PATH_MAX];         /* resolved /proc/<pid>/exe, "" if unknown */
    Bool privileged;
    Bool identified;
    CARD32 lastFocus;           /* ms timestamp the client last held focus */
    unsigned loggedReasons;     /* bitmask: each deny reason logged once */
};

/* deny reasons; also the log vocabulary */
enum XFocusOnlyReason {
    XFOCUSONLY_KEY_NOT_FOCUSED = 0,
    XFOCUSONLY_RAW_KEY,
    XFOCUSONLY_KEY_STATE,
    XFOCUSONLY_GRAB_FOREIGN_WINDOW,
    XFOCUSONLY_REPLAY_KEYBOARD,
    XFOCUSONLY_EXT_RECORD,
    XFOCUSONLY_SELECTION_NOT_FOCUSED,
    XFOCUSONLY_NUM_REASONS
};

static const char *reasonName[XFOCUSONLY_NUM_REASONS] = {
    [XFOCUSONLY_KEY_NOT_FOCUSED]       = "key-event-without-focus",
    [XFOCUSONLY_RAW_KEY]               = "xi2-raw-key-event",
    [XFOCUSONLY_KEY_STATE]             = "keyboard-state-read",
    [XFOCUSONLY_GRAB_FOREIGN_WINDOW]   = "passive-key-grab-on-foreign-window",
    [XFOCUSONLY_REPLAY_KEYBOARD]       = "replay-keyboard",
    [XFOCUSONLY_EXT_RECORD]            = "record-extension",
    [XFOCUSONLY_SELECTION_NOT_FOCUSED] = "selection-read-without-focus",
};

static DevPrivateKeyRec clientPrivKeyRec;

static inline struct XFocusOnlyClient *
XFocusOnlyOf(ClientPtr client)
{
    if (!client)
        return NULL;
    return dixLookupPrivate(&client->devPrivates, &clientPrivKeyRec);
}

/* ---- privilege config ---------------------------------------------------- */

static char **privExes = NULL;
static int numPrivExes = 0;

static void
loadConfig(void)
{
    const char *path = getenv("XFOCUSONLY_CONF");
    if (!path || !*path)
        path = XFOCUSONLY_DEFAULT_CONF;

    FILE *f = fopen(path, "r");
    if (!f) {
        LogMessageVerb(X_INFO, 0, "xfocusonly: no config at %s; no client is privileged\n", path);
        return;
    }

    char line[PATH_MAX + 2];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
            *--e = '\0';
        if (*s == '\0' || *s == '#')
            continue;
        char **grown = realloc(privExes, sizeof(char *) * (numPrivExes + 1));
        if (!grown)
            FatalError("xfocusonly: out of memory\n");
        privExes = grown;
        privExes[numPrivExes++] = strdup(s);
    }
    fclose(f);
    LogMessageVerb(X_INFO, 0, "xfocusonly: %d privileged executable(s) from %s\n", numPrivExes, path);
}

static Bool
exeIsPrivileged(const char *exe)
{
    for (int i = 0; i < numPrivExes; i++)
        if (strcmp(privExes[i], exe) == 0)
            return TRUE;
    return FALSE;
}

/* ---- identity ------------------------------------------------------------ */

static void
identify(ClientPtr client)
{
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);
    LocalClientCredRec *lcc;

    g->identified = TRUE;
    if (GetLocalClientCreds(client, &lcc) == -1)
        return;                 /* not a local socket: unknown, unprivileged */
    if (lcc->fieldsSet & LCC_PID_SET)
        g->pid = lcc->pid;
    FreeLocalClientCreds(lcc);
    if (!g->pid)
        return;

    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", g->pid);
    ssize_t n = readlink(link, g->exe, sizeof(g->exe) - 1);
    if (n < 0) {
        g->exe[0] = '\0';
        return;
    }
    g->exe[n] = '\0';
    g->privileged = exeIsPrivileged(g->exe);
    LogMessageVerb(X_INFO, 3, "xfocusonly: client #%d pid=%d exe=%s%s\n",
                   client->index, g->pid, g->exe, g->privileged ? " (privileged)" : "");
}

static void
HookClientState(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    NewClientInfoRec *info = calldata;
    ClientPtr client = info->client;
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);

    switch (client->clientState) {
    case ClientStateInitial:
        memset(g, 0, sizeof(*g));
        identify(client);
        break;
    case ClientStateRunning:
        if (!g->identified)
            identify(client);
        break;
    default:
        break;
    }
}

static Bool
IsPrivileged(ClientPtr client)
{
    if (!client || client == serverClient)
        return TRUE;
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);
    return g && g->privileged;
}

/* ---- focus --------------------------------------------------------------- */

static Bool
keyboardFocusedOn(DeviceIntPtr kbd, ClientPtr client, WindowPtr pWin)
{
    if (kbd->deviceGrab.grab && rClient(kbd->deviceGrab.grab) == client)
        return TRUE;
    if (!kbd->focus)
        return FALSE;

    WindowPtr f = kbd->focus->win;
    if (f == FollowKeyboardWin)
        f = inputInfo.keyboard->focus->win;
    if (f == NoneWin || f == NULL)
        return FALSE;
    if (f == PointerRootWin)
        /* keys go to the window under the pointer: fine if that is the
           recipient's own (non-root) window */
        return pWin && pWin->parent && wClient(pWin) == client;
    return wClient(f) == client;
}

/* True if `client` currently owns keyboard focus (on any master keyboard),
 * or holds an active keyboard grab. Records the time for the grace period. */
static Bool
ClientHasFocus(ClientPtr client, WindowPtr pWin)
{
    for (DeviceIntPtr dev = inputInfo.devices; dev; dev = dev->next) {
        if (!IsMaster(dev) || !dev->key)
            continue;
        if (keyboardFocusedOn(dev, client, pWin)) {
            struct XFocusOnlyClient *g = XFocusOnlyOf(client);
            if (g)
                g->lastFocus = GetTimeInMillis();
            return TRUE;
        }
    }
    return FALSE;
}

/* Parent pid of `pid` from /proc/<pid>/stat, or 0. */
static int
parentPid(int pid)
{
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* "pid (comm) state ppid ..." - comm may contain spaces and parens */
    char *p = strrchr(buf, ')');
    int ppid = 0;
    if (!p || sscanf(p + 1, " %*c %d", &ppid) != 1)
        return 0;
    return ppid;
}

/* True if `client` runs in a process descended from a focus owner's process:
 * a tool launched from the focused terminal inherits its right to the
 * clipboard, a background daemon does not. */
static Bool
ClientDescendsFromFocus(ClientPtr client)
{
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);
    if (!g || !g->pid)
        return FALSE;

    int pid = g->pid;
    for (int depth = 0; depth < 32; depth++) {
        pid = parentPid(pid);
        if (pid <= 1)
            return FALSE;
        for (int i = 1; i < currentMaxClients; i++) {
            ClientPtr other = clients[i];
            if (!other || other == client)
                continue;
            struct XFocusOnlyClient *og = XFocusOnlyOf(other);
            if (og && og->pid == pid && ClientHasFocus(other, NULL))
                return TRUE;
        }
    }
    return FALSE;
}

static Bool
ClientHadFocusRecently(ClientPtr client)
{
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);
    return g && g->lastFocus &&
        (GetTimeInMillis() - g->lastFocus) <= XFOCUSONLY_FOCUS_GRACE_MS;
}

/* ---- logging ------------------------------------------------------------- */

static void
Deny(ClientPtr client, enum XFocusOnlyReason reason, const char *detail)
{
    struct XFocusOnlyClient *g = XFocusOnlyOf(client);
    if (!g || (g->loggedReasons & (1u << reason)))
        return;                 /* one line per client and reason */
    g->loggedReasons |= 1u << reason;
    LogMessageVerb(X_INFO, 0, "xfocusonly deny client=%d pid=%d exe=%s reason=%s%s%s\n",
                   client->index, g->pid, g->exe[0] ? g->exe : "?",
                   reasonName[reason], detail ? " " : "", detail ? detail : "");
}

/* ---- rules 1, 2: event delivery ----------------------------------------- */

static void
HookReceive(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    XaceReceiveAccessRec *param = calldata;
    ClientPtr client = param->client;

    for (int i = 0; i < param->count; i++) {
        const xEvent *ev = &param->events[i];
        const int type = ev->u.u.type & 0x7f;
        Bool isKey = FALSE, isRaw = FALSE;

        if (type == KeyPress || type == KeyRelease)
            isKey = TRUE;
        else if (type == DeviceKeyPress || type == DeviceKeyRelease)
            isKey = TRUE;
        else if (type == GenericEvent) {
            const xGenericEvent *ge = (const xGenericEvent *) ev;
            if (ge->extension == IReqCode) {
                if (ge->evtype == XI_KeyPress || ge->evtype == XI_KeyRelease)
                    isKey = TRUE;
                else if (ge->evtype == XI_RawKeyPress || ge->evtype == XI_RawKeyRelease)
                    isRaw = TRUE;
            }
        }

        if (!isKey && !isRaw)
            continue;
        if (IsPrivileged(client))
            continue;
        if (isRaw) {
            Deny(client, XFOCUSONLY_RAW_KEY, NULL);
            param->status = BadAccess;
            return;
        }
        if (!ClientHasFocus(client, param->pWin)) {
            Deny(client, XFOCUSONLY_KEY_NOT_FOCUSED, NULL);
            param->status = BadAccess;
            return;
        }
    }
}

/* ---- rules 3, 4, 5: keyboard state, passive grabs, replay ---------------- */

static Bool
ownsWindow(ClientPtr client, Window id)
{
    WindowPtr pWin;
    if (dixLookupWindow(&pWin, id, client, DixGetAttrAccess) != Success)
        return FALSE;
    return wClient(pWin) == client;
}

static void
HookDevice(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    XaceDeviceAccessRec *param = calldata;
    ClientPtr client = param->client;
    DeviceIntPtr dev = param->dev;

    if (!client || !dev || !dev->key || IsPrivileged(client))
        return;

    const int major = client->majorOp, minor = client->minorOp;
    const Bool xi = (major == IReqCode);
    const void *req = client->requestBuffer;
    enum XFocusOnlyReason reason;
    Window grabWindow = None;

    if (major == X_QueryKeymap || (xi && minor == X_QueryDeviceState)) {
        if (ClientHasFocus(client, NULL))
            return;
        reason = XFOCUSONLY_KEY_STATE;
        goto deny;
    }

    if (major == X_GrabKey)
        grabWindow = ((const xGrabKeyReq *) req)->grabWindow;
    else if (xi && minor == X_GrabDeviceKey)
        grabWindow = ((const xGrabDeviceKeyReq *) req)->grabWindow;
    else if (xi && minor == X_XIPassiveGrabDevice) {
        const xXIPassiveGrabDeviceReq *r = req;
        if (r->grab_type != XIGrabtypeKeycode)
            return;
        grabWindow = r->grab_window;
    }
    if (grabWindow != None) {
        if (ownsWindow(client, grabWindow))
            return;
        reason = XFOCUSONLY_GRAB_FOREIGN_WINDOW;
        goto deny;
    }

    if (major == X_AllowEvents) {
        if (((const xAllowEventsReq *) req)->mode != ReplayKeyboard)
            return;
        reason = XFOCUSONLY_REPLAY_KEYBOARD;
        goto deny;
    }
    if (xi && minor == X_XIAllowEvents) {
        if (((const xXIAllowEventsReq *) req)->mode != XIReplayDevice)
            return;
        reason = XFOCUSONLY_REPLAY_KEYBOARD;
        goto deny;
    }
    return;

deny:
    Deny(client, reason, NULL);
    param->status = BadAccess;
}

/* ---- rule 7: RECORD ------------------------------------------------------ */

static Bool
isRecord(const ExtensionEntry *ext)
{
    return ext && strcmp(ext->name, "RECORD") == 0;
}

static void
HookExtAccess(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    XaceExtAccessRec *param = calldata;
    /* answered "not present"; harmless and probed by every client, so not logged */
    if (isRecord(param->ext) && !IsPrivileged(param->client))
        param->status = BadAccess;
}

static void
HookExtDispatch(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    XaceExtAccessRec *param = calldata;
    if (isRecord(param->ext) && !IsPrivileged(param->client)) {
        Deny(param->client, XFOCUSONLY_EXT_RECORD, NULL);
        param->status = BadAccess;
    }
}

/* ---- rule 8: clipboard --------------------------------------------------- */

static void
HookSelection(CallbackListPtr *pcbl, void *unused, void *calldata)
{
    XaceSelectionAccessRec *param = calldata;
    ClientPtr client = param->client;

    if (client->majorOp != X_ConvertSelection || !(param->access_mode & DixReadAccess))
        return;
    if (IsPrivileged(client) || ClientHasFocus(client, NULL) ||
        ClientHadFocusRecently(client) || ClientDescendsFromFocus(client))
        return;

    Deny(client, XFOCUSONLY_SELECTION_NOT_FOCUSED, NameForAtom((*param->ppSel)->selection));
    /* BadMatch is what an unowned selection returns: ProcConvertSelection
       then sends the requestor a SelectionNotify with property None and the
       owner never sees the request. */
    param->status = BadMatch;
}

/* ---- init ---------------------------------------------------------------- */

void
XFocusOnlyExtensionInit(void)
{
    loadConfig();

    if (!(dixRegisterPrivateKey(&clientPrivKeyRec, PRIVATE_CLIENT,
                                sizeof(struct XFocusOnlyClient)) &&
          AddCallback(&ClientStateCallback, HookClientState, NULL) &&
          XaceRegisterCallback(XACE_RECEIVE_ACCESS, HookReceive, NULL) &&
          XaceRegisterCallback(XACE_DEVICE_ACCESS, HookDevice, NULL) &&
          XaceRegisterCallback(XACE_EXT_ACCESS, HookExtAccess, NULL) &&
          XaceRegisterCallback(XACE_EXT_DISPATCH, HookExtDispatch, NULL) &&
          XaceRegisterCallback(XACE_SELECTION_ACCESS, HookSelection, NULL)))
        FatalError("xfocusonly: allocation failure\n");

    LogMessageVerb(X_INFO, 0, "xfocusonly: active\n");
}
