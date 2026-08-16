// Patched benchmark equivalent with no command shell.
package main

import (
	"net/http"
	"os/exec"
	"regexp"
)

var safeTarget = regexp.MustCompile(`^[a-z0-9.-]{1,64}$`)

func diagnostics(response http.ResponseWriter, request *http.Request) {
	target := request.URL.Query().Get("target")
	if !safeTarget.MatchString(target) {
		http.Error(response, "invalid target", http.StatusBadRequest)
		return
	}
	output, _ := exec.Command("/usr/bin/dig", target).Output()
	response.Write(output)
}
