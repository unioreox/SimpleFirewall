# SimpleFirewall - Go实现的简易防火墙(用户自动认证白名单),目前是基本能用的半成品
- 基于iptables && ip6tables实现
- 目前功能仅限于用户验证和添加白名单
- 理论上可以提高节点安全性，抗封锁，降低主动探测风险
- 目前已支持IPv4与IPv6双栈（由于Turnstile无法识别IPv6地址,IPv6地址将直接通过验证）
- 使用Cloudflare Turnstile进行用户验证，减小错判率
- 理论支持任何安装有iptables的Linux系统
- 支持使用Toml配置文件，无需动态配置
- 界面支持定制化，可以自行修改模板文件(html/auth.html && html/result.html)来优化界面
- 限制验证次数，防止恶意攻击，默认次数为5次，可在源码中修改，后续会在配置文件中跟进（未测试）
- 计划支持：TelegramBot手动动态删减IP白名单;

### 配置指南
- 配置文件路径: 程序同目录下的 conf.toml 文件
- 配置文件示例:
```toml
TemplatePath = "/usr/local/etc/sfw/html" # 模板文件路径，必需
LogPath = "/var/log/SimpleFirewall.log" # 日志文件路径，必需
UserPort = 12321 # 用户需要认证才能访问的端口，必需
AuthPort = 22588 # 认证程序端口，必需
TurnstileSiteKey = "0x4AAAAAAACMHRDyJ_vifS1F" # Cloudflare Turnstile SiteKey，必需
TurnstileSecretKey = "0x4AAAAAAACMHZaUN7iX5nO6vbsm6q0m4d8" # Cloudflare Turnstile SecretKey，必需
TelegramAdmin = 0 # Telegram管理员ID，不必需，未开发完毕
TelegramToken = "" # Telegram Bot Token，不必需，未开发完毕
TLSCert = "" # SSL证书路径，不必需
TLSKey = "" # SSL密钥路径，不必需
Commands = [
    ""
] # 需要执行的防止iptables冲突的命令，例如: iptables -F 等，不必需，但是建议在已经使用iptables的服务器上配置，防止冲突
```

### 安装指南
- 拉取并编译项目（[确保Golang已安装](https://go.dev/doc/install)）
```shell
git clone https://github.com/unioreox/SimpleFirewall.git && cd SimpleFirewall
go build
```
- 运行项目
```
./SimpleFirewall -c [配置文件路径]
```

### UI定制指南
- UI模板文件路径: 程序同目录下的 html : auth.html && result.html
```
auth.html  //认证界面模板
- {{Turnstile-SiteKey}}   Cloudflare人机验证Turnstile的SiteKey
- {{IP}}                  访问者IP

result.html  //结果显示界面模板
- {{MESSAGE}}             成功或失败消息
```

## Credits
[Toml-GoLib](https://github.com/pelletier/go-toml)  
[Cloudflare-Turnstile](https://github.com/cloudflare)  

您的每一个Star都是我们改进的动力
