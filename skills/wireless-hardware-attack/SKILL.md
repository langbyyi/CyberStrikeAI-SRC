---
name: wireless-hardware-attack
description: >-
  无线/硬件:WiFi PMKID/WPS/Evil Twin,BLE,Zigbee,NFC,SDR,UART/JTAG/SPI,侧信道,故障注入。Use when attacking WiFi, BLE, RFID, SDR, or hardware interfaces.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 无线 / 硬件攻击

```
=== 无线/硬件 ===
WiFi: aircrack-ng/PMKID(hcxdumptool+hashcat)/WPS reaver/Evil Twin | BLE: gatttool枚举GATT/无认证读写/Just Works
Zigbee killerbee | NFC/RFID proxmark3克隆/MIFARE mfoc | LoRa/SDR rtl-sdr+gnuradio重放
硬件: UART波特率扫描拿shell | JTAG/SWD读写固件 | SPI flash dump | 侧信道DPA/时序 | 故障注入(电压/时钟毛刺跳认证) | binwalk -Me
```

