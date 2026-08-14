---
name: blockchain-contract-attack
description: >-
  区块链/智能合约:Etherscan,slither/mythril,重入/访问控制/预言机/闪电贷,跨链桥,RPC暴露。Use when auditing smart contracts, DeFi, or blockchain attack surfaces.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 区块链 / 智能合约

```
=== 区块链/智能合约 ===
源码: Etherscan getsourcecode API | 审计 slither/mythril/manticore
手工: 重入(.call{value}先转账后改状态违反C-E-I) | 访问控制(onlyOwner缺失) | 整数溢出(<0.8无SafeMath)
  预言机操纵(闪电贷瞬时操纵AMM价格) | 随机数(block.timestamp可控) | 授权滥用(无限approve/permit重放) | delegatecall代理storage冲突
DeFi: 闪电贷攻击/三明治(抢跑)/治理攻击/签名重放 | 跨链桥:签名阈值绕过/重放 | RPC:暴露8545直接eth_sendTransaction
```
