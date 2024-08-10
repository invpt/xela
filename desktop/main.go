package main

import (
	"errors"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"

	webview "github.com/webview/webview_go"
)

type runningState int

const (
	runningStateReady runningState = iota
	runningStateReadyDegraded
	runningStateRunning
	runningStateRunningDegraded
)

func main() {
	devMode := os.Getenv("XELA_DEV_MODE") == "1"

	w := webview.New(devMode)
	defer w.Destroy()
	w.SetTitle("Basic Example")
	w.SetSize(480, 320, webview.HintNone)

	var state atomic.Int32
	state.Store(int32(runningStateReady))

	address, serveErrors, err := startHttpServer()
	if err != nil {
		state.Store(int32(runningStateReadyDegraded))
	}

	go (func() {
		for err := range serveErrors {
			canceled := state.CompareAndSwap(int32(runningStateReady), int32(runningStateReadyDegraded))

			var message string
			if canceled {
				message = "<p>xela's internal HTTP server couldn't be started :(</p>"
			} else {
				message = "<p>xela's internal HTTP server crashed :(</p>"
				state.Store(int32(runningStateRunningDegraded))
			}

			w.SetHtml(fmt.Sprint(message, "<pre>", html.EscapeString(err.Error()), "</pre>"))
		}
	})()

	initialPath := "/index.html"
	if devMode {
		initialPath = "/index.dev.html"

		w.Bind("devReloadUi", func() {
			fmt.Println("UI reload starting...")
			cmd := exec.Command("make", "build-ui")
			err := cmd.Start()
			if err != nil {
				panic(err)
			}
			err = cmd.Wait()
			if err != nil {
				panic(err)
			}

			w.Eval("window.location.reload()")
			fmt.Println("UI reloaded.")
		})
	}

	w.Navigate(fmt.Sprint("http://", address, initialPath))
	if !state.CompareAndSwap(int32(runningStateReady), int32(runningStateRunning)) {
		state.Store(int32(runningStateRunningDegraded))
	}
	w.Run()
}

func startHttpServer() (addr string, serveErrors <-chan error, err error) {
	bidiServeErrors := make(chan error)
	serveErrors = bidiServeErrors

	http.HandleFunc("/", getRoot)

	for {
		const MinDynPort = 49152
		const MaxDynPort = 65535
		port := rand.Intn(MaxDynPort-MinDynPort+1) + MinDynPort

		addr = fmt.Sprint("127.0.0.1:", port)

		var l net.Listener
		l, err = net.Listen("tcp", addr)
		if err != nil {
			if isErrorAddressAlreadyInUse(err) {
				continue
			} else {
				return
			}
		}

		go (func() {
			if err := http.Serve(l, nil); err != nil {
				bidiServeErrors <- err
			}
		})()

		break
	}

	return
}

// https://stackoverflow.com/a/65865898
func isErrorAddressAlreadyInUse(err error) bool {
	var eOsSyscall *os.SyscallError
	if !errors.As(err, &eOsSyscall) {
		return false
	}
	var errErrno syscall.Errno // doesn't need a "*" (ptr) because it's already a ptr (uintptr)
	if !errors.As(eOsSyscall, &errErrno) {
		return false
	}
	if errors.Is(errErrno, syscall.EADDRINUSE) {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Method, r.URL.Path)
	f, err := os.Open(filepath.Join("ui", r.URL.Path))
	if err != nil {
		panic(err)
	}
	io.Copy(w, f)
}
