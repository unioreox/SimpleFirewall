# SimpleFirewall - Go实现的简易防火墙(用户自动认证白名单)
- 基于iptables实现
- 目前功能仅限于用户验证和添加白名单
- 理论上可以提高节点安全性，抗封锁，降低主动探测风险
- 目前仅支持IPv4, 未来会通过ip6tables支持IPv6
- 使用Cloudflare Turnstile进行用户验证，减小错判率
- 理论支持任何安装有iptables的Linux系统
- 支持使用Toml配置文件，无需动态配置
- 界面支持定制化，可以自行修改模板文件(html/auth.html && html/result.html)来优化界面


### 配置指南
- 配置文件路径: 程序同目录下的 conf.toml 文件
- 配置文件示例:
```toml
UserPort = 12321 # 用户需要认证才能访问的端口，必需
AuthPort = 22588 # 认证程序端口，必需
TurnstileSiteKey = "0x4AAAAAAACMHRDyJ_vifS1F" # Cloudflare Turnstile SiteKey，必需
TurnstileSecretKey = "0x4AAAAAAACMHZaUN7iX5nO6vbsm6q0m4d8" # Cloudflare Turnstile SecretKey，必需
Commands = [
    ""
] # 需要执行的防止iptables冲突的命令，例如: iptables -F 等，不必需，但是建议在已经使用iptables的服务器上配置，防止冲突
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
- [Toml-GoLib]("https://github.com/pelletier/go-toml")
- [Cloudflare-Turnstile]("https://github.com/cloudflare")  

您的每一个Star都是我们改进的动力
