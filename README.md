# IP-Hacker

俄罗斯大黑客用的 IP 地址检测工具

Supported Provider:
- Baidu
- Bilibili
- Cloudflare
- cz88.net
- db-ip.com
- freeaiapi.com
- httpbin.org
- ip2location.io
- ip125.com
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
- ipdata.co
- ipgeolocation.io
- ipinfo.io
- ipip.net
- ipquery.io
- ipw.cn
- ipwho.is
- ipwhois.app
- itdog.cn
- myip.la
- myip.wtf
- vvhan.com

## 一键安装脚本

```bash
bash <(wget -qO- -o- https://raw.githubusercontent.com/rsbench/IP-Hacker/refs/heads/main/install.sh)
```

该脚本会自动安装到本地路径 `./IP-Hacker`

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
  -s, --set-ip <SET_IP>  IP Address
      --no-cls           No CLS
      --no-logo          No Logo
      --no-upload        No Upload
      --no-logger        No Logger Output
      --json             Json Output
  -h, --help             Print help
  -V, --version          Print version

```

## Demo

```
> ./IP-Hacker
 Provider    | IP                       | ASN    | ISP                                         | Country   | Region                       | City 
-------------+--------------------------+--------+---------------------------------------------+-----------+------------------------------+------------
 Ipinfo.io   | 154.92.xxx.xx            | 398704 | STACKS INC                                  | HK        | Central and Western          | Central 
 Ipinfo.io   | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile Communications Group Co., Ltd. | CN        | Shanghai                     | Shanghai 
 Maxmind     | 154.92.xxx.xx            | 398704 | STACKSINC-BACKBONE                          | Hong Kong | N/A                          | N/A 
 Maxmind     | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile Communications Group Co., Ltd. | China     | Guangxi                      | Nanning 
 IpCheck.ing | 154.92.xxx.xx            | 398704 | Stacks Inc                                  | Hong Kong | Central and Western District | Mid Levels 
 IpCheck.ing | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile                                | China     | Guangxi                      | Guangzhou 
```

```
> ./IP-Hacker -a
 Provider    | IP                       | ASN    | ISP                                         | Country   | Region                       | City       | Lat     | Lon      | Time Zone      | Risk | Tags 
-------------+--------------------------+--------+---------------------------------------------+-----------+------------------------------+------------+---------+----------+----------------+------+------
 Ipinfo.io   | 154.92.xxx.xx            | 398704 | STACKS INC                                  | HK        | Central and Western          | Central    | 22.2830 | 114.1585 | Asia/Hong_Kong | N/A  |  
 Ipinfo.io   | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile Communications Group Co., Ltd. | CN        | Shanghai                     | Shanghai   | 31.2222 | 121.4581 | Asia/Shanghai  | N/A  |  
 Maxmind     | 154.92.xxx.xx            | 398704 | STACKSINC-BACKBONE                          | Hong Kong | N/A                          | N/A        | 22.2578 | 114.1657 | N/A            | N/A  |  
 Maxmind     | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile Communications Group Co., Ltd. | China     | Guangxi                      | Nanning    | 22.8111 | 108.3168 | N/A            | N/A  |  
 IpCheck.ing | 154.92.xxx.xx            | 398704 | Stacks Inc                                  | Hong Kong | Central and Western District | Mid Levels | 22.273  | 114.15   | N/A            | N/A  |  
 IpCheck.ing | 2409:xxxx:xxxx:xxxx::xxx | 9808   | China Mobile                                | China     | Guangxi                      | Guangzhou  | 23.4849 | 111.274  | N/A            | N/A  |  
```

```
> ./IP-Hacker --provider --ip --isp
 Provider    | IP                       | ISP 
-------------+--------------------------+---------------------------------------------
 Ipinfo.io   | 154.92.xxx.xx            | STACKS INC 
 Ipinfo.io   | 2409:xxxx:xxxx:xxxx::xxx | China Mobile Communications Group Co., Ltd. 
 Maxmind     | 154.92.xxx.xx            | STACKSINC-BACKBONE 
 Maxmind     | 2409:xxxx:xxxx:xxxx::xxx | China Mobile Communications Group Co., Ltd. 
 IpCheck.ing | 154.92.xxx.xx            | Stacks Inc 
 IpCheck.ing | 2409:xxxx:xxxx:xxxx::xxx | China Mobile 
```

```
> ./IP-Hacker --set-ip 1.1.1.1
 Provider    | IP      | ASN   | ISP              | Country   | Region     | City 
-------------+---------+-------+------------------+-----------+------------+----------------
 Ipinfo.io   | 1.1.1.1 | 13335 | Cloudflare, Inc. | AU        | Queensland | Brisbane 
 Maxmind     | 1.1.1.1 | 13335 | CLOUDFLARENET    | N/A       | N/A        | N/A 
 IpCheck.ing | 1.1.1.1 | 13335 | Cloudflare, Inc  | Australia | Queensland | South Brisbane
```
