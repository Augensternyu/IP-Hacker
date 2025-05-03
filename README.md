# IP-Hacker

俄罗斯大黑客用的 IP 地址检测工具

Usage:
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
      --no-color         No Color
      --no-cls           No CLS
      --no-logo          No Logo
      --no-upload        No Upload
  -h, --help             Print help
  -V, --version          Print version
```

Demo:
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
