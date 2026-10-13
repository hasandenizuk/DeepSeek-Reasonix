package computer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// maxWait bounds a wait step: a pause longer than this is a task that should
// come back rather than one call holding the turn.
const maxWait = 30 * time.Second

// refusedApps are never operated, whatever the person approves: input there
// reaches past the boundaries the host keeps everywhere else. A security list,
// kept as one: macOS bundle ids, and Windows process file names or a Store
// application's package family name.
var refusedApps = map[string]string{
	"electron":                    "Reasonix Studio itself",
	"applicationframehost.exe":    "an application broker without an unambiguous executable identity",
	"io.reasonix.studio":          "Reasonix Studio itself",
	"com.github.Electron":         "Reasonix Studio itself",
	"com.apple.Terminal":          "a terminal",
	"com.googlecode.iterm2":       "a terminal",
	"dev.warp.Warp-Stable":        "a terminal",
	"net.kovidgoyal.kitty":        "a terminal",
	"com.mitchellh.ghostty":       "a terminal",
	"org.alacritty":               "a terminal",
	"com.apple.keychainaccess":    "the keychain",
	"com.apple.Passwords":         "a password manager",
	"com.1password.1password":     "a password manager",
	"com.agilebits.onepassword7":  "a password manager",
	"com.bitwarden.desktop":       "a password manager",
	"com.apple.systempreferences": "System Settings",
	"com.apple.SecurityAgent":     "a system authorization prompt",

	"reasonix studio.exe":                            "Reasonix Studio itself",
	"electron.exe":                                   "Reasonix Studio itself",
	"windowsterminal.exe":                            "a terminal",
	"microsoft.windowsterminal_8wekyb3d8bbwe":        "a terminal",
	"microsoft.windowsterminalpreview_8wekyb3d8bbwe": "a terminal",
	"openconsole.exe":                                "a terminal",
	"conhost.exe":                                    "a terminal",
	"cmd.exe":                                        "a terminal",
	"powershell.exe":                                 "a terminal",
	"pwsh.exe":                                       "a terminal",
	"mintty.exe":                                     "a terminal",
	"wezterm-gui.exe":                                "a terminal",
	"alacritty.exe":                                  "a terminal",
	"1password.exe":                                  "a password manager",
	"bitwarden.exe":                                  "a password manager",
	"keepass.exe":                                    "a password manager",
	"keepassxc.exe":                                  "a password manager",
	"credentialuibroker.exe":                         "a system authorization prompt",
	"consent.exe":                                    "a system authorization prompt",
	"windows.immersivecontrolpanel_cw5n1h2txyewy": "Windows Settings",
	"systemsettings.exe":                          "Windows Settings",
	"regedit.exe":                                 "the registry editor",
	"mmc.exe":                                     "a system management console",
	"taskmgr.exe":                                 "Task Manager",
	"powershell_ise.exe":                          "a terminal",
	"conemu.exe":                                  "a terminal",
	"conemu64.exe":                                "a terminal",
	"wt.exe":                                      "a terminal",
	"microsoft.powershell_8wekyb3d8bbwe":          "a terminal",
	"microsoft.sechealthui_8wekyb3d8bbwe":         "Windows Security",
	"reasonix studio":                             "Reasonix Studio itself",
	"reasonix-studio":                             "Reasonix Studio itself",
	"gnome-terminal-server":                       "a terminal",
	"konsole":                                     "a terminal",
	"xterm":                                       "a terminal",
	"kitty":                                       "a terminal",
	"alacritty":                                   "a terminal",
	"wezterm-gui":                                 "a terminal",
	"gnome-control-center":                        "system settings",
	"systemsettings":                              "system settings",
	"seahorse":                                    "the keychain",
	"keepassxc":                                   "a password manager",
	"bitwarden":                                   "a password manager",
	"1password":                                   "a password manager",
}

// refusedFolded is refusedApps compared without case: Windows file names are
// case-insensitive, and a refusal must not be one capital letter from missing.
var refusedFolded = func() map[string]string {
	m := make(map[string]string, len(refusedApps))
	for name, why := range refusedApps {
		m[strings.ToLower(name)] = why
	}
	return m
}()

// Refused reports why an application is never operated, or "" when it may be.
func Refused(bundle string) string {
	identity, _, _ := strings.Cut(strings.TrimSpace(bundle), "!")
	return refusedFolded[strings.ToLower(identity)]
}

// App is a running application a person can see.
type App struct {
	PID    int32  `json:"pid"`
	Bundle string `json:"bundle"`
	// Exe is a Windows application's file name when Bundle is its package
	// family name; a refusal holds under either.
	Exe     string   `json:"exe,omitempty"`
	Name    string   `json:"name"`
	Active  bool     `json:"active"`
	Windows []Window `json:"windows"`
}

// Window is one of an application's windows on screen, in global points.
type Window struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Bounds Rect   `json:"bounds"`
}

// Rect is a rectangle in global points, origin top-left.
type Rect struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type Session struct {
	driver *Driver
	name   string
	state  observation
}

type observation struct {
	generation    uint64
	app           App
	window        Window
	refs          map[string]string
	capture       string
	imageWidth    int
	imageHeight   int
	captureWidth  int
	captureHeight int
}

func NewSession(driver *Driver) *Session {
	return &Session{driver: driver, name: "reasonix-" + rand.Text()}
}

func (s *Session) read(ctx context.Context, name string, args map[string]any, out any) (DriverResult, error) {
	args["session"] = s.name
	var result DriverResult
	if err := s.driver.Call(ctx, name, args, &result); err != nil {
		s.state = observation{}
		return result, err
	}
	if out != nil {
		if len(result.Structured) == 0 {
			return result, fail(CodeFailed, "CUA omitted structured result")
		}
		if err := json.Unmarshal(result.Structured, out); err != nil {
			return result, fail(CodeFailed, "invalid CUA result: %v", err)
		}
	}
	return result, nil
}

func (s *Session) Apps(ctx context.Context) ([]App, error) {
	s.driver.desktop.Lock()
	defer s.driver.desktop.Unlock()
	return s.apps(ctx)
}

func (s *Session) apps(ctx context.Context) ([]App, error) {
	var response struct {
		Apps []struct {
			PID     int32  `json:"pid"`
			Bundle  string `json:"bundle_id"`
			Name    string `json:"name"`
			Active  bool   `json:"active"`
			Running bool   `json:"running"`
		} `json:"apps"`
	}
	if _, err := s.read(ctx, "list_apps", map[string]any{}, &response); err != nil {
		return nil, err
	}
	var apps []App
	for _, a := range response.Apps {
		if !a.Running || a.PID <= 0 {
			continue
		}
		bundle, exe, err := processIdentity(a.PID, a.Bundle)
		if err != nil {
			continue
		}
		var windows struct {
			Windows []struct {
				ID     int    `json:"window_id"`
				PID    int32  `json:"pid"`
				Title  string `json:"title"`
				Bounds Rect   `json:"bounds"`
			} `json:"windows"`
		}
		if _, err := s.read(ctx, "list_windows", map[string]any{"pid": a.PID}, &windows); err != nil {
			return nil, err
		}
		app := App{PID: a.PID, Bundle: bundle, Exe: exe, Name: a.Name, Active: a.Active}
		for _, w := range windows.Windows {
			if w.PID == a.PID && w.ID > 0 {
				app.Windows = append(app.Windows, Window{ID: w.ID, Title: w.Title, Bounds: w.Bounds})
			}
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func (s *Session) app(ctx context.Context, bundle string) (App, error) {
	bundle = strings.TrimSpace(bundle)
	if why := Refused(bundle); why != "" {
		return App{}, fail(CodeAppRefused, "%s is %s", bundle, why)
	}
	apps, err := s.apps(ctx)
	if err != nil {
		return App{}, err
	}
	var found []App
	for _, app := range apps {
		if app.Bundle == bundle {
			if why := Refused(app.Exe); why != "" {
				return App{}, fail(CodeAppRefused, "%s is %s", bundle, why)
			}
			found = append(found, app)
		}
	}
	if len(found) == 0 {
		return App{}, fail(CodeNoApp, "no running application has identity %q", bundle)
	}
	if len(found) > 1 {
		return App{}, fail(CodeNoApp, "application identity %q resolves to multiple processes", bundle)
	}
	return found[0], nil
}

func exactWindow(app App, ids []int) (Window, error) {
	if len(ids) > 0 && ids[0] > 0 {
		for _, w := range app.Windows {
			if w.ID == ids[0] {
				return w, nil
			}
		}
		return Window{}, fail(CodeNoWindow, "window does not belong to this application")
	}
	if len(app.Windows) != 1 {
		return Window{}, fail(CodeNoWindow, "select an exact window id; application has %d windows", len(app.Windows))
	}
	return app.Windows[0], nil
}

type Step struct {
	Action string   `json:"action"`
	Ref    string   `json:"ref,omitempty"`
	Text   string   `json:"text,omitempty"`
	Key    string   `json:"key,omitempty"`
	X      *float64 `json:"x,omitempty"`
	Y      *float64 `json:"y,omitempty"`
	// scroll: lines to turn the wheel by, negative downwards; wait: how long.
	Amount float64 `json:"amount,omitempty"`
	Ms     int     `json:"ms,omitempty"`
	// Where a pointer drag ends, which button a pointer click uses, and how many
	// times a click or a key repeats.
	ToX    *float64 `json:"to_x,omitempty"`
	ToY    *float64 `json:"to_y,omitempty"`
	Button string   `json:"button,omitempty"`
	Times  int      `json:"times,omitempty"`
	// hold_key: how long the key stays down.
	Seconds float64 `json:"seconds,omitempty"`
}

// PointerStep reports whether a step takes the person's pointer rather than
// going through the application's own accessibility actions. The two are
// authorised apart: one asks an element to act, the other moves the pointer the
// person is holding.
func PointerStep(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "pointer_move", "pointer_click", "pointer_drag", "pointer_position":
		return true
	}
	return false
}

// PointerSteps reports whether any of these steps takes the pointer.
func PointerSteps(steps []Step) bool {
	return slices.ContainsFunc(steps, func(s Step) bool { return PointerStep(s.Action) })
}

type StepResult struct {
	Note   string
	Effect Effect
}

type ActResult struct {
	App      App
	Done     int
	Steps    []StepResult
	FailedAt int
}

func (s *Session) Act(ctx context.Context, bundle string, steps []Step, windows ...int) (ActResult, error) {
	s.driver.desktop.Lock()
	defer s.driver.desktop.Unlock()
	res := ActResult{FailedAt: -1}
	app, err := s.app(ctx, bundle)
	if err != nil {
		res.FailedAt = 0
		return res, err
	}
	res.App = app
	window, err := exactWindow(app, windows)
	if err != nil {
		res.FailedAt = 0
		return res, err
	}
	for i, step := range steps {
		if err := ctx.Err(); err != nil {
			s.state = observation{}
			res.FailedAt = i
			return res, err
		}
		done, err := s.step(ctx, app, window, step)
		if err == nil || done.Effect.Class != "" {
			res.Done++
			res.Steps = append(res.Steps, done)
		}
		if err != nil {
			res.FailedAt = i
			return res, err
		}
	}
	return res, nil
}
