# VelaDNS

[English](README.md) | 简体中文

VelaDNS 是一个面向 RouterOS、Mihomo 和普通 Docker 主机的故障关闭型分流
DNS 容器，包含：

- MosDNS 5.3.4：请求路由、缓存、指标和 DNS 监听；
- 两个 Unbound 1.25.1 实例：本地递归 CN 分类器，以及支持 DNSSEC 验证的
  加密解析器；
- 带提供商故障切换和退避的进程内 DoH 网桥；
- 可选的 Mihomo DNS fake-IP 集成；
- 独立的子进程监督和功能型健康检查。

IPv6 应答固定关闭。运行策略由两个环境变量和两个持久化域名列表控制，不依赖
Redis，内置规则源也不会在运行时下载或刷新。

## 请求流程

```text
客户端 -> :53
  -> 规则快速路径
  -> 否则进入 :5305 递归分类
       -> CN 地址：直接返回
       -> 非 CN：丢弃原应答 -> :5306 验证 -> :5307 DoH
                                      -> 可选 Mihomo fake-IP

Mihomo 查询真实 DNS -> :5304 -> :5306 -> :5307 -> DoH/443
```

请求严格按照以下顺序判断：

1. 拒绝 AAAA 和私有域名；
2. 检查“直连”映射；
3. 检查“代理”映射；
4. 使用 `cncidr.txt` 根据递归 A 应答对未知域名做最终分类。

| 决策 | 结果 |
| --- | --- |
| 直连 | 返回经过加密传输和 DNSSEC 验证的真实地址 |
| 代理 | 启用 Mihomo 时返回 fake-IP；故障或纯安全模式下返回加密真实地址 |
| 未知域名 | CN 应答直接返回；非 CN 应答被丢弃并通过加密路径重新解析 |
| AAAA | 返回成功但无记录的应答 |
| 私有域名 | 返回 `NXDOMAIN` |

VelaDNS 不缓存 fake-IP。DNSSEC 验证失败保持为 `SERVFAIL`，`NXDOMAIN` 和
NODATA 不会被转换成 fake-IP。

## 快速开始

纯加密真实 IP 模式：

```sh
docker run -d \
  --name veladns \
  --restart unless-stopped \
  -v ./data:/data \
  -p 53:53/udp -p 53:53/tcp \
  -p 5304:5304/udp -p 5304:5304/tcp \
  -p 127.0.0.1:5308:5308/tcp \
  ghcr.io/hyird/veladns:latest
```

Mihomo fake-IP 模式：

```sh
docker run -d \
  --name veladns \
  --restart unless-stopped \
  -v ./data:/data \
  -e AUTO_FORWARD=172.16.0.101 \
  -p 53:53/udp -p 53:53/tcp \
  -p 5304:5304/udp -p 5304:5304/tcp \
  -p 127.0.0.1:5308:5308/tcp \
  ghcr.io/hyird/veladns:latest
```

端口 `53` 是面向客户端的分流 DNS。端口 `5304` 始终返回加密真实地址，可安全
用作 Mihomo 的真实 DNS 上游。端口 `5308` 只应允许可信监控主机访问。

仓库同时提供 [docker-compose.yml](docker-compose.yml) 和可审查的
[RouterOS 模板](routeros/install.rsc)。

## 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LOG_LEVEL` | `warn` | `debug`、`info`、`warn` 或 `error` |
| `AUTO_FORWARD` | `no` | `no` 或 Mihomo DNS 的 `host[:port]`，默认端口为 `53` |

`AUTO_FORWARD` 支持主机名或 IPv4 端点，不支持 IPv6 字面量。VelaDNS 与该
DNS 端点之间使用 TCP。

启用 Mihomo 后：

- `proxy.txt` 映射中的 A 查询直接进入 Mihomo；
- `direct.txt` 映射中的查询始终通过加密、DNSSEC 验证的真实解析；
- 未知域名只有在真实应答被判定为非 CN 后才进入 Mihomo；
- 未知域名已有的验证结果会被复用为降级应答，TTL 固定为 5 秒；
- `proxy.txt` 映射域名没有预存真实应答，Mihomo 故障时会重新走加密解析；
- 连续失败 5 次后打开熔断器；每次查询尝试 2 次，每次 800 毫秒，带抖动的
  重试延迟最大为 30 秒；
- 半开探测成功后自动恢复转发。

加密路径为 `Unbound -> 127.0.0.1:5307 -> DoH/443`，DNSSEC 由 Unbound
在本地验证。启用 Mihomo 时，DoH 网桥优先通过 Mihomo 使用 NextDNS 和
Quad9，随后降级到直连 Cloudflare 和 360。提供商域名的 bootstrap 查询通过
TCP 发送给 Mihomo。DoH 提供商连续失败 2 次后进入退避，最大延迟为 5 分钟。

日志只写入标准输出和标准错误。下游 TCP 客户端的预期断开会单独计数，不产生
WARN 噪声，也不增加 DNS `err_total`。在 `warn` 级别下，Unbound 只输出错误；
可自动恢复的 DoH 启动探测通过提供商指标保留；当请求入口已经记录失败时，内部
同一查询的 deadline 告警不再重复输出。组件退出、熔断状态变化、全部 DNS 提供商
不可用以及客户端可见的请求失败仍保留为可操作告警。

## 端口

非标准端口连续排列，并按请求层级排序：

| 端口 | 绑定 | 作用 |
| --- | --- | --- |
| `53` | `0.0.0.0`，UDP/TCP | 面向客户端的分流 DNS |
| `5304` | `0.0.0.0`，UDP/TCP | 面向 Mihomo 的加密真实 IP 监听 |
| `5305` | `127.0.0.1` | 递归 CN 分类器 |
| `5306` | `127.0.0.1` | 支持 DNSSEC 验证的 Unbound |
| `5307` | `127.0.0.1` | 进程内 DoH 网桥 |
| `5308` | `0.0.0.0`，HTTP | 健康检查、指标和性能分析 |

镜像声明端口 `53`、`5304` 和 `5308`。`5305` 至 `5307` 始终留在容器内部。
示例配置将 `5308` 绑定到宿主机回环地址。

## 健康检查

Go 入口进程分别监督 MosDNS 和两个 Unbound 进程。子进程退出后会独立重启，
带抖动的重启延迟最大为 30 秒。

| 接口 | 含义 |
| --- | --- |
| `/plugins/veladns/livez` | supervisor 状态新鲜且 MosDNS 正在运行 |
| `/plugins/veladns/readyz` | 在 livez 基础上检查 DoH 网桥和解析器依赖 |
| `/plugins/veladns/healthz` | `readyz` 的兼容别名 |
| `/plugins/veladns/dependencies` | 组件和 DoH 提供商状态的 JSON 快照 |

验证型或递归型 Unbound 故障时状态为 `degraded`；supervisor 状态过期、MosDNS
停止或 DoH 网桥不可用时状态为 unhealthy。容器健康检查会先调用 `readyz`，
再通过 `127.0.0.1:5304` 执行一次真实 A 查询，因此不会只依赖 HTTP 状态。

## 指标

Prometheus 指标地址：

```text
http://127.0.0.1:5308/metrics
```

主要指标族：

| 指标族 | 作用 |
| --- | --- |
| `mosdns_metrics_collector_*` | main/secure 查询总数、真实错误、客户端取消、并发和延迟 |
| `mosdns_veladns_decisions_total` | 按请求顺序记录路由和分类决策 |
| `mosdns_veladns_doh_upstream_*` | 各 DoH 提供商的请求、成功、失败、耗时、退避和时间戳 |
| `mosdns_veladns_component_*` | 受监督进程的状态、重启次数和重启退避 |
| `mosdns_veladns_circuit_*` | Mihomo 熔断状态、失败、绕过次数和重试延迟 |
| `mosdns_veladns_client_cancel_events_total` | 从 WARN 日志中抑制的预期 TCP 取消事件 |

MosDNS 还会导出 Go/进程、缓存和带标签的上游转发指标。同一 HTTP 监听器的
`/debug/pprof` 下提供性能分析接口。禁止向不可信网络开放端口 `5308`。

## 自定义规则

VelaDNS 对外只提供两个域名映射：

| 映射 | 用户维护文件 | 内置基础数据 | 结果 |
| --- | --- | --- | --- |
| 直连 | `direct.txt` | 无 | 返回经过加密和 DNSSEC 验证的真实地址，绕过 fake-IP |
| 代理 | `proxy.txt` | 固定版本的代理规则 | Mihomo fake-IP，故障时返回加密真实地址 |

这两个 `/data` 文件只允许填写域名规则，不应写入 IP 或 CIDR。旧的
`real-ip.txt`、`overseas.txt` 与 `domestic.txt` 不会自动迁移；升级前如需保留
其中规则，先手动合并到 `direct.txt` 或 `proxy.txt`。

内置代理规则和 `cncidr.txt` 都是固定版本的内部数据，不属于用户维护列表。
`cncidr.txt` 是未知应答分类所用的 IP 网段库。

规则使用 MosDNS 域名语法：

```text
domain:example.com
full:www.example.com
keyword:example
regexp:^api[0-9]+\.example\.com$
```

`direct.txt` 和 `proxy.txt` 由 MosDNS 进程持续监听，保存后会在约 200 毫秒
防抖窗口后热更新，不重启容器或 DNS 监听器。空文件会清空对应规则；注释、空行
和非法规则会被自动移除。若一次修改全部为非法规则，则恢复该文件上一次有效内容，
避免意外丢失现有分流。可写 DNSSEC 信任锚保存在 `/run/veladns/unbound`，不会
写入 `/data`。

## RouterOS 与 Mihomo

仓库中的 RouterOS 模板默认使用：

- VelaDNS：`172.16.0.100`
- Mihomo：`172.16.0.101`
- 容器网桥：`172.16.0.0/16`

导入 [routeros/install.rsc](routeros/install.rsc) 前必须检查接口名、路径、
地址和防火墙插入位置。

Mihomo 应使用 VelaDNS 的 `5304` 端口查询真实地址：

```yaml
dns:
  enable: true
  listen: :53
  enhanced-mode: fake-ip
  nameserver:
    - 172.16.0.100:5304
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - 114.114.114.114
```

`proxy-server-nameserver` 必须独立于 VelaDNS，确保 Mihomo 能在 bootstrap
阶段解析代理节点主机名。订阅和控制面域名应同时加入 `direct.txt` 与
Mihomo 的 `fake-ip-filter`。

## 验证与发布

运行集成测试：

```sh
go test ./...
go vet ./...
docker build -t veladns:test .
sh tests/integration.sh veladns:test
```

测试覆盖纯安全模式和 Mihomo 模式、UDP/TCP 监听、CN/非 CN 分类、直接
fake-IP 快速路径、DNSSEC/NXDOMAIN/NODATA、健康检查、指标、故障降级、
熔断恢复、子进程重启和环境变量校验。

GitHub Actions 会测试 `linux/amd64`，对 `linux/arm64` 和 `linux/arm/v7`
执行冒烟测试，并在非 PR 流程全部通过后发布带 SBOM 和 provenance 的多架构
GHCR 镜像。规则归档和 Go 模块图均通过校验和或版本固定。发布二进制经过
UPX `--best --lzma` 压缩；准备好的 Alpine 文件系统整体复制到 scratch 阶段，
因此每个平台清单严格只有一个文件系统层。CI 会检查层数，并在所有发布架构上
实际执行压缩后的二进制。

CI 为 AMD64、ARM64 和 ARMv7 分别维护 BuildKit 缓存。发布任务直接复用三份
已经测试过的缓存，不再重新编译每个平台；Go 测试和 vet 只在集成镜像构建前
执行一次。

第三方组件和数据许可证见
[THIRD_PARTY.zh-CN.md](THIRD_PARTY.zh-CN.md)。
