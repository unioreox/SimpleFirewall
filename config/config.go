package config

import (
	"github.com/pelletier/go-toml/v2"
	"io"
	"os"
)

type SFWConfig struct {
	LogPath            string //日志路径
	UserPort           int    //访问端口
	AuthPort           int    //认证端口
	TurnstileSiteKey   string //人机验证sitekey
	TurnstileSecretKey string //人机验证secretkey
	TelegramToken      string //Telegram机器人token
	TelegramAdmin      int64  //Telegram管理员ID
	TLSCert            string //TLS证书
	TLSKey             string //TLS密钥
	Commands           []string
}

func ReadConfig(filePath string) SFWConfig {
	//读取配置文件
	file, err1 := os.Open(filePath)
	getError(err1)
	defer file.Close()
	configRaw, err2 := io.ReadAll(file)
	getError(err2)
	var config SFWConfig
	toml.Unmarshal(configRaw, &config)
	return config
}

func ReadTemplate(filePath string) string {
	file, err1 := os.Open(filePath)
	getError(err1)
	defer file.Close()
	templateRaw, err2 := io.ReadAll(file)
	getError(err2)
	return string(templateRaw)
}
func getError(e error) {
	if e != nil {
		panic(e)
	}
}
