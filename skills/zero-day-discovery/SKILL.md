---
name: zero-day-discovery
description: >-
  0day自主发现引擎:变体分析/补丁间隙/差分/Fuzzing/污点推理/N-day武器化/猎人思维。Use when public vulns not found and need to discover 0day or weaponize N-day.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 0day 自主发现引擎（全网搜不到漏洞时自己挖）

```
核心转变: 从"匹配已知漏洞库"→"理解代码/协议怎么工作,推断它哪里会坏"。0day不是运气,是方法。
五条主路:
  1.变体分析(最高产): 拿一个CVE补丁→提炼漏洞模式→全库grep同模式其它位置→补丁没覆盖的=0day
  2.补丁间隙: 读补丁过滤逻辑,黑名单几乎总能绕(漏了某种编码/等价函数/别名)→新CVE
  3.差分测试: 两组件对同一输入理解不一致(WAF vs 后端/校验器 vs 执行器)→走私/SSRF绕过
  4.Fuzzing: 写harness(包住处理不可信输入的函数)+造语料/字典+崩溃triage(可复现/可控/可利用性)
     AFL++/libFuzzer(覆盖率引导找内存破坏) boofuzz(协议) radamsa(黑盒) restler(REST API)
  5.污点推理(有源码最强): source(参数/Header/反序列化字段)无有效sanitizer到sink(exec/SQL/模板)=0day
     CodeQL写query自动求数据流可达 / Semgrep / Joern
N-day武器化(advisory出了但全网无PoC): 从补丁diff逆向重建exploit(bindiff/diaphora二进制对比,
  厂商regression test常就是PoC雏形)→本地试验场调通→打目标。漏洞窗口期最大化,红队最值钱能力之一。
猎人思维(看任何代码/端点/协议逐层逼问,每个"是"都是0day候选):
  信任边界:假设输入可信吗?什么情况不成立? | 状态时序:两步间状态能改吗(TOCTOU)?能打乱顺序吗?
  解析规范化:解析几次?normalize在校验前还是后? | 边界极值:负数/0/超大/类型混淆/编码/null字节?
  隐含能力:这功能"顺便"给了我什么? | 唯一性:ID/token可预测吗?"秘密"真是秘密吗?
把组件变"假设清单"逐个打破: 文件上传隐含假设"只传图片/扩展名可信/文件名不含路径/内容只是数据"→逐个打破=漏洞,组合=链。
0day验证(比CVE要求更高): 可复现(最小PoC)+根因清楚(哪行/哪个假设)+影响可证(实际读写执行)+排除误报。
```

