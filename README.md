# IP-Hacker

![](https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Frsbench%2Frsbench&label=&icon=github&color=%23160d27) ![](https://img.shields.io/crates/v/IP-Hacker) ![](https://tokei.rs/b1/github/rsbench/IP-Hacker)

![IP-Hacker](https://socialify.git.ci/rsbench/IP-Hacker/image?custom_description=%E4%B8%80%E6%AC%BE%E8%B7%A8%E5%B9%B3%E5%8F%B0%E3%80%81%E9%AB%98%E6%80%A7%E8%83%BD%E3%80%81%E6%98%93%E4%BD%BF%E7%94%A8%E3%80%81CLI+%E5%8F%8B%E5%A5%BD%E7%9A%84+IP+%E6%89%B9%E9%87%8F%E6%A3%80%E6%B5%8B%E5%B7%A5%E5%85%B7&description=1&font=Jost&forks=1&language=1&name=1&owner=1&pattern=Circuit+Board&stargazers=1&theme=Auto)

俄罗斯大黑客用的 IP 地址检测工具

> [!WARNING]
> `俄罗斯大黑客` 只是一个玩笑，请勿当真

> [!NOTE]
> 本软件所用 API 均来自于互联网，若有任何问题请在 Issue 提出

## About

相比于一般的 Bash IP 检测脚本，有何优势？
- `速度超快`: **Powered By RUST!**，别问，问就是比 Bash 处理快 (尽管瓶颈还是在网络请求) \
    除开网络请求，处理 100 个 IP 信息只需要 6ms (包括解析、输出、格式化)
- `支持服务商多`: 现已支持 50+ API 服务商查询，涵盖了大部分常用的 API
- `CLI 程序 / 用户界面友好`: 有两种输出格式，**Json 输出**可传递给其他程序继续处理；**表格输出**为默认，便于用户阅读；既可作为其他项目依赖，也可直接调用
- `便于拓展`: 只要有一点点的编程基础，就可以为本项目贡献各种 API，相关的请往下看
- `可自定义程度高`: 支持自定义输出格式 / 列表
- `多平台支持`: 由于使用编译型语言，可以简单地实现**跨平台支持**，不像 Bash 脚本仅 Linux，还需要很多依赖
- ... 总之就是很多

相关链接:
- Github Repo: <https://github.com/rsbench/IP-Hacker>
- TG Channel: <https://t.me/rsbench>
- TG Chat: <https://t.me/rsbench_chat>
- Blog: https://c1oudf1are.eu.org/p/hackerip


<details>
  <summary>目前已经支持 56+ 个 API 提供商</summary>

  - abstractapi.com
  - apiip.net
  - apilayer.com
  - apip.cc
  - Baidu
  - biantailajiao.com
  - Bilibili
  - Cloudflare
  - cz88.net
  - dashi.163.com
  - db-ip.com
  - freeaiapi.com
  - groapify.com
  - geoplugin.net
  - hsselite.com
  - httpbin.org
  - ip2location.io
  - ip125.com
  - ip233.cn
  - ip234.in
  - ip-api.com
  - ipcheck.ing
  - ipcheck.ing Maxmind
  - iplark.com Digital Element
  - iplark.com Ip-Api
  - iplark.com IpData
  - iplark.com IpStack
  - iplark.com Maxmind
  - iplark.com Moe
  - iplark.com Moon
  - ip.sb
  - ipapi.co
  - ipapi.is
  - ipbase.com
  - ipdata.co
  - ipgeolocation.io
  - ipinfo.io
  - ipip.net
  - ipleak.net
  - iplocation.net
  - ipquery.io
  - ipw.cn
  - ipwho.is
  - ipwhois.app
  - itdog.cn
  - keycdn.com
  - maptiler.com
  - meituan.com
  - myip.la
  - myip.wtf
  - nameless13.xyz
  - qq.com
  - realip.cc
  - reallyfreegeoip.org
  - taobao.com
  - vvhan.com

</details>

## Demo

![alt text](<https://53e534f.webp.li/p/hackerip/2025-06-24 04-49-49.gif>)

![alt text](https://53e534f.webp.li/p/hackerip/image.png)

![alt text](https://53e534f.webp.li/p/hackerip/image-1.png)

## 安装

### 一键脚本

```bash
bash <(wget -qO- -o- https://raw.githubusercontent.com/rsbench/IP-Hacker/refs/heads/main/install.sh)
```

仅支持 Linux，且特殊发行版有概率不正常

安装到本地的 `./IP-Hacker`

### Binary 安装

安装非常简单，只需要下载一个 Binary 可执行文件即可:

在 [Github Release](https://github.com/rsbench/IP-Hacker/releases/tag/latest) 下载

![alt text](https://53e534f.webp.li/p/hackerip/image-2.png)

关于 Binary 的选择: 

`Windows x86_64` 直接选择 `IP-Hacker.exe`

`Macos` 请根据自己的芯片选择:
- `IP-Hacker-macos-amd64`
- `IP-Hacker-macos-arm64`

`Linux` 编译架构众多，基本命名为: `IP-Hacker-linux-[ARCH]-[RUNTIME]`

架构我就不说了，关键是 Runtime (也就是对应平台特性 / 依赖库)

对于正常发行版 (如 Ubuntu / Debian 新版本)，直接选择带有 `gnu` 后缀的即可

对于不使用 `Glibc` 的发行版 (如 OpenWrt / Alpine)，直接选择带有 `musl` 后缀的即可

当然，任意发行版均可运行带有 `musl` 后缀的 Binary

## Usage
```
IP tools used by Russia's big hackers

Usage: 

Options:
  -a, --all              Show All Information
      --provider         Show Provider Name
      --ip               Show IP Address
      --asn              Show ASN
      --isp              Show ISP Name
      --country          Show Country
      --region           Show Region
      --city             Show City
      --coordinates      Show Coordinates
      --time-zone        Show Time Zone
      --risk             Show Risk Score
      --tags             Show Risk Tags
      --time             Show Processing Time
  -s, --set-ip <SET_IP>  Set IP Address
      --cls              No CLS
      --no-logo          No Logo
      --no-upload        No Upload
      --logger           Logger Output
      --json             Json Output
  -h, --help             Print help
  -V, --version          Print version
```

## Usage Demo

<details>
  <summary>直接运行</summary>

  ```bash
  ./IP-Hacker
  ```

  ![RIwPKKnQ3WNR5ZkEsc0sXTEgBPBXuhFZ.webp](https://www.nodeimage.com/i/9617/RIwPKKnQ3WNR5ZkEsc0sXTEgBPBXuhFZ.png)

</details>

<details>
  <summary>输出所有支持的信息</summary>

  ```bash
  ./IP-Hacker --all
  ```

  ![GNZSriny3WNR5bdCsc0sxIfaCZ0DjPnX.webp](https://www.nodeimage.com/i/9617/GNZSriny3WNR5bdCsc0sxIfaCZ0DjPnX.png)

</details>

<details>
  <summary>只输出 Provider 与 IP 和 Country</summary>

  > [!TIP]
  > 还有更多的搭配，请自行尝试

  ```bash
  ./IP-Hacker --provider --ip --country
  ```

  ![e2mVtKn13WNR5Zl9sc0smZwcLEFT92xw.webp](https://www.nodeimage.com/i/9617/e2mVtKn13WNR5Zl9sc0smZwcLEFT92xw.png)

</details>

<details>
  <summary>查询指定 IP</summary>

  ```bash
  ./IP-Hacker --set-ip 11.45.1.4
  ```

  ![IYeSaXnp3WNR5YfFsc0sIxtpkPjBXReA.webp](https://www.nodeimage.com/i/9617/IYeSaXnp3WNR5YfFsc0sIxtpkPjBXReA.png)

</details>

<details>
  <summary>Json 输出</summary>

  ```bash
  ./IP-Hacker --json | jq
  ```

  ![R1b4zpnR3WNR5WiGsc0s4UXMlVEG3NXV.webp](https://www.nodeimage.com/i/9617/R1b4zpnR3WNR5WiGsc0s4UXMlVEG3NXV.png)

  输出过多，仅截取部分

</details>

## Stars Map

![](https://starchart.cc/rsbench/IP-Hacker.svg)

## LICENSE

本项目根据 WTFPL 许可证开源

```
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
```