// Deliberately vulnerable benchmark fixture. Do not deploy.
package main

import (
	"net/http"
	"os/exec"
)

func diagnostics(response http.ResponseWriter, request *http.Request) {
	command := request.URL.Query().Get("command")
	output, _ := exec.Command("sh", "-c", command).Output()
	response.Write(output)
}
