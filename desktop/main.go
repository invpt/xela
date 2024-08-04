package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	webview "github.com/webview/webview_go"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Basic Example")
	w.SetSize(480, 320, webview.HintNone)
	w.Navigate(fmt.Sprint("file://", filepath.Join(cwd, "ui", "index.html")))
	w.Run()
}
