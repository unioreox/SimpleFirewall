package main

import (
	sfwconfig "SimpleFirewall/config"
	"SimpleFirewall/telegram"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	go run()
	go telegram.RunBot()
}
func run() {
	fmt.Println("SimpleFirewall正在启动...")
	fmt.Println("读取配置...")
	//读取配置文件
	config := sfwconfig.ReadConfig("./conf.toml")
	fmt.Println("执行防冲突及初始化命令")
	//执行配置文件中初始化及防止冲突命令
	for index, value := range config.Commands {
		fmt.Println("执行第" + strconv.Itoa(index+1) + "条命令")
		err := runCommand(value)
		getError(err)
	}
	fmt.Println("防冲突及初始化命令执行完毕")

	//配置iptables规则
	fmt.Println("检查IPv4 iptables规则...")
	//检查IPv4规则是否存在
	//放行认证端口(tcp)
	commandAuthCheckError := runCommand("iptables -C INPUT -p tcp --dport " + strconv.Itoa(config.AuthPort) + " -j ACCEPT")
	//禁用用户端口
	commandUserCheckErrorTCP := runCommand("iptables -C INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
	commandUserCheckErrorUDP := runCommand("iptables -C INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")

	fmt.Println("检查IPv6 iptables规则...")
	//检查IPv6规则是否存在
	//放行认证端口(tcp)
	commandAuthCheckError6 := runCommand("ip6tables -C INPUT -p tcp --dport " + strconv.Itoa(config.AuthPort) + " -j ACCEPT")
	//禁用用户端口
	commandUserCheckErrorTCP6 := runCommand("ip6tables -C INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
	commandUserCheckErrorUDP6 := runCommand("ip6tables -C INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")

	//判断iptables规则是否存在
	if commandAuthCheckError == nil || commandAuthCheckError6 == nil {
		fmt.Println("放行认证端口(tcp) 规则已存在,不更改")
	} else {
		fmt.Println("放行认证端口(tcp) 规则不存在,正在添加")
		commandAuthAcceptError := runCommand("iptables -A INPUT -p tcp --dport " + strconv.Itoa(config.AuthPort) + " -j ACCEPT")
		getError(commandAuthAcceptError)
		commandAuthAcceptError6 := runCommand("ip6tables -A INPUT -p tcp --dport " + strconv.Itoa(config.AuthPort) + " -j ACCEPT")
		getError(commandAuthAcceptError6)
	}

	if commandUserCheckErrorTCP == nil || commandUserCheckErrorUDP == nil || commandUserCheckErrorTCP6 == nil || commandUserCheckErrorUDP6 == nil {
		fmt.Println("禁用用户端口(tcp+udp) 规则已存在,不更改")
	} else {
		fmt.Println("禁用用户端口(tcp+udp) 规则不存在,正在添加")
		commandUserDropErrorTCP := runCommand("iptables -A INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
		getError(commandUserDropErrorTCP)
		commandUserDropErrorTCP6 := runCommand("ip6tables -A INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
		getError(commandUserDropErrorTCP6)
		commandUserDropErrorUDP := runCommand("iptables -A INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
		getError(commandUserDropErrorUDP)
		commandUserDropErrorUDP6 := runCommand("ip6tables -A INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
		getError(commandUserDropErrorUDP6)
	}
	fmt.Println("iptables规则检查完毕")
	//配置完毕
	//启动认证服务器
	http.HandleFunc("/auth", auth)
	if config.TLSCert != "" && config.TLSKey != "" {
		fmt.Println("已启动HTTPS认证服务器")
		httpListenError := http.ListenAndServeTLS(":"+strconv.Itoa(config.AuthPort), config.TLSCert, config.TLSKey, nil)
		getError(httpListenError)
	} else {
		fmt.Println("已启动HTTP服务器")
		httpListenError := http.ListenAndServe(":"+strconv.Itoa(config.AuthPort), nil)
		getError(httpListenError)
	}

}
func auth(w http.ResponseWriter, r *http.Request) {
	config := sfwconfig.ReadConfig("./conf.toml")
	r.ParseForm()
	authToken := r.Form.Get("cf-turnstile-response")
	if authToken == "" {
		remoteAddr := r.RemoteAddr
		ipAddr, parseIPError := netip.ParseAddrPort(remoteAddr)
		getError(parseIPError)
		ip := ipAddr.Addr().String()
		isIPv6 := ipAddr.Addr().Is6()
		if isIPv6 {
			commandCheckError := runCommand("ip6tables -C INPUT -s " + ip + " -j ACCEPT")
			resultHTML := sfwconfig.ReadTemplate("./html/result.html")
			if commandCheckError == nil {
				resultHTML = strings.Replace(resultHTML, "{{MESSAGE}}", "恭喜您，您的IP："+ip+" 已存在", -1)
			} else {
				resultHTML = strings.Replace(resultHTML, "{{MESSAGE}}", "恭喜您，您的IP："+ip+" 已通过认证", -1)
			}
			//删除原规则
			commandUserDeleteErrorTCP := runCommand("ip6tables -D INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
			getError(commandUserDeleteErrorTCP)
			commandUserDeleteErrorUDP := runCommand("ip6tables -D INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
			getError(commandUserDeleteErrorUDP)
			commandAcceptError := runCommand("ip6tables -A INPUT -s " + ip + " -j ACCEPT")
			getError(commandAcceptError)
			commandUserDropErrorTCP := runCommand("ip6tables -A INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
			getError(commandUserDropErrorTCP)
			commandUserDropErrorUDP := runCommand("ip6tables -A INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
			getError(commandUserDropErrorUDP)
			w.WriteHeader(200)
			w.Write([]byte(resultHTML))
		} else {
			authHTML := sfwconfig.ReadTemplate("./html/auth.html")
			authHTML = strings.Replace(authHTML, "{{IP}}", ip, -1)
			authHTML = strings.Replace(authHTML, "{{Turnstile-SiteKey}}", sfwconfig.ReadConfig("./conf.toml").TurnstileSiteKey, -1)
			w.Write([]byte(authHTML))
		}
	} else {
		result, postError := http.Post("https://challenges.cloudflare.com/turnstile/v0/siteverify", "application/x-www-form-urlencoded", strings.NewReader("secret="+sfwconfig.ReadConfig("./conf.toml").TurnstileSecretKey+"&response="+authToken))
		getError(postError)
		defer result.Body.Close()
		body, readError := io.ReadAll(result.Body)
		getError(readError)
		var resultJSON map[string]interface{}
		jsonError := json.Unmarshal(body, &resultJSON)
		getError(jsonError)
		if resultJSON["success"].(bool) {
			remoteAddr := r.RemoteAddr
			ipAddr, parseIPError := netip.ParseAddrPort(remoteAddr)
			getError(parseIPError)
			ip := ipAddr.Addr().String()
			resultHTML := sfwconfig.ReadTemplate("./html/result.html")

			var commandCheckError error
			isIPv4 := ipAddr.Addr().Is4()
			if isIPv4 {
				commandCheckError = runCommand("iptables -C INPUT -s " + ip + " -j ACCEPT")
			}
			if commandCheckError == nil {
				resultHTML = strings.Replace(resultHTML, "{{MESSAGE}}", "恭喜您，您的IP："+ip+" 已存在", -1)
			} else {
				resultHTML = strings.Replace(resultHTML, "{{MESSAGE}}", "恭喜您，您的IP："+ip+" 已通过认证", -1)

				if isIPv4 {
					//删除原规则
					commandUserDeleteErrorTCP := runCommand("iptables -D INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
					getError(commandUserDeleteErrorTCP)
					commandUserDeleteErrorUDP := runCommand("iptables -D INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
					getError(commandUserDeleteErrorUDP)
					commandAcceptError := runCommand("iptables -A INPUT -s " + ip + " -j ACCEPT")
					getError(commandAcceptError)
					commandUserDropErrorTCP := runCommand("iptables -A INPUT -p tcp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
					getError(commandUserDropErrorTCP)
					commandUserDropErrorUDP := runCommand("iptables -A INPUT -p udp --dport " + strconv.Itoa(config.UserPort) + " -j DROP")
					getError(commandUserDropErrorUDP)
				}
			}
			w.WriteHeader(200)
			w.Write([]byte(resultHTML))
		} else {
			remoteAddr := r.RemoteAddr
			ipAddr, parseIPError := netip.ParseAddrPort(remoteAddr)
			getError(parseIPError)
			ip := ipAddr.Addr().String()
			resultHTML := sfwconfig.ReadTemplate("./html/result.html")
			resultHTML = strings.Replace(resultHTML, "{{MESSAGE}}", "很遗憾，您的IP："+ip+"未通过认证", -1)
			w.WriteHeader(200)
			w.Write([]byte(resultHTML))
		}
	}
}

func getError(e error) {
	if e != nil {
		panic(e)
	}
}

func runCommand(command string) error {
	_, err := exec.Command("/bin/bash", "-c", command).Output()
	return err
}
