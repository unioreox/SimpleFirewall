package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

var port = 22688  //访问端口
var aport = 12321 //认证端口

func main() {
	fmt.Println("SFW正在启动...")
	fmt.Println("输入您需要用户认证访问的端口(1-65535 默认为22688)：")
	//用户输入访问端口
	fmt.Scanln(&port)
	//判断端口是否合法
	if port < 1 || port > 65535 {
		fmt.Println("端口不合法 1-65535")
		return
	}
	fmt.Println("输入您需要搭建认证程序的端口(1-65535 默认为12321)：")
	//等待用户输入认证端口
	fmt.Scanln(&aport)
	//判断端口是否合法
	if aport < 1 || aport > 65535 {
		fmt.Println("端口不合法 1-65535")
		return
	}
	//放行认证端口(udp+tcp)
	s1 := execShell("iptables -A INPUT -p tcp --dport " + strconv.Itoa(aport) + " -j ACCEPT")
	//检查访问端口
	s2tcpc := execShell("iptables -C INPUT -p tcp --dport " + strconv.Itoa(port) + " -j DROP")
	s2udpc := execShell("iptables -C INPUT -p udp --dport " + strconv.Itoa(port) + " -j DROP")
	if s2tcpc != nil || s2udpc != nil {
		//关闭访问端口
		s2tcp := execShell("iptables -A INPUT -p tcp --dport " + strconv.Itoa(port) + " -j DROP")
		s2udp := execShell("iptables -A INPUT -p udp --dport " + strconv.Itoa(port) + " -j DROP")
		//判断是否放行成功
		if s1 == nil && s2tcp == nil && s2udp == nil {
			fmt.Println("端口设置成功")
		} else {
			fmt.Println("端口设置失败")
			return
		}
	} else {
		fmt.Println("您已配置过该配置，恢复中")
	}
	//建立web服务器

	http.Handle("/auth", http.HandlerFunc(doAuthentication))
	http.Handle("/", http.FileServer(http.Dir("./html/")))
	fmt.Println("认证程序启动中...如未报错则启动成功")
	err := http.ListenAndServe("0.0.0.0:"+strconv.Itoa(aport), nil)
	if err != nil {
		fmt.Println("认证程序启动失败")
		fmt.Println(err.Error())
		return
	}
}

// 后端验证处理函数
func doAuthentication(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("获取HTTP请求错误: " + err.Error())
		w.WriteHeader(404)
		w.Write([]byte("<h1>Not Verified</h1>"))
		return
	}
	//判断是否ipv4
	ip := r.RemoteAddr
	length := len(strings.Split(ip, ":"))
	if length > 2 {
		fmt.Println("Non-IPv4 Detected" + ip)
		w.WriteHeader(404)
		w.Write([]byte("<h1>IPv4 Only</h1>"))
	} else {
		//reCaptcha后端验证
		k := r.Form.Get("g-recaptcha-response")
		url := "https://www.google.com/recaptcha/api/siteverify"
		payload := strings.NewReader("response=" + k + "&secret=6Lc0py4kAAAAAJO9jEA5CEEna9RRIM7ZrIS3yMg4")
		ar, err := http.Post(url, "application/x-www-form-urlencoded", payload)
		if err != nil {
			fmt.Println("验证提交错误: " + err.Error())
			w.WriteHeader(404)
			w.Write([]byte("<h1>Not Verified</h1>"))
			return
		}
		defer ar.Body.Close()
		result := make(map[string]interface{})
		body, _ := io.ReadAll(ar.Body)
		json.Unmarshal(body, &result)
		if result["success"].(bool) == false {
			fmt.Println("reCaptcha Failed: " + ip)
			w.WriteHeader(404)
			w.Write([]byte("<h1>Not Verified</h1>"))
			return
		}
		rip := strings.Split(ip, ":")[0]

		//判断规则是否存在

		s3 := execShell("iptables -C INPUT -p tcp --dport " + strconv.Itoa(port) + " -s " + rip + " -j ACCEPT")
		s4 := execShell("iptables -C INPUT -p udp --dport " + strconv.Itoa(port) + " -s " + rip + " -j ACCEPT")
		if s3 == nil || s4 == nil {
			fmt.Println("Already Exists: " + rip)
			w.Write([]byte("<h1>Already Exists! " + rip + "</h1>"))
			return
		}
		//放行访问端口
		s5 := execShell("iptables -A INPUT -p tcp --dport " + strconv.Itoa(port) + " -s " + rip + " -j ACCEPT")
		s6 := execShell("iptables -A INPUT -p udp --dport " + strconv.Itoa(port) + " -s " + rip + " -j ACCEPT")
		s7tcp := execShell("iptables -D INPUT -p tcp --dport " + strconv.Itoa(port) + " -j DROP")
		s7udp := execShell("iptables -D INPUT -p udp --dport " + strconv.Itoa(port) + " -j DROP")
		s8tcp := execShell("iptables -A INPUT -p tcp --dport " + strconv.Itoa(port) + " -j DROP")
		s8udp := execShell("iptables -A INPUT -p udp --dport " + strconv.Itoa(port) + " -j DROP")

		if s5 == nil && s6 == nil && s7tcp == nil && s7udp == nil && s8tcp == nil && s8udp == nil {
			fmt.Println("IPv4 Detected: " + rip)
			w.Write([]byte("<h1>Success! " + rip + "</h1>"))
			return
		} else {
			fmt.Println("IPv4 Detected: " + rip)
			w.WriteHeader(404)
			w.Write([]byte("<h1>Not Verified</h1>"))
			return
		}
	}
}

func execShell(command string) error {
	c := exec.Command("sh", "-c", command)
	r := c.Run()
	return r
}
