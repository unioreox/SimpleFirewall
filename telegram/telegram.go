package telegram

import (
	sfwconfig "SimpleFirewall/config"
	"os/exec"
)

func main() {
	RunBot()
}
func RunBot() {
	//库不好用，搁置了
}

func getError(e error) {
	if e != nil {
		panic(e)
	}
}

func runCommand(command string) (string, error) {
	output, error := exec.Command("/bin/bash", "-c", command).Output()
	return string(output), error
}

func checkConfig(config sfwconfig.SFWConfig) {
	if config.TelegramAdmin == 0 || config.TelegramToken == "" {
		return
	}
}
