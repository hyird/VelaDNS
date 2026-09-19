# 第三方组件

[English](THIRD_PARTY.md)

VelaDNS 镜像包含以下第三方程序、库和数据：

- [MosDNS](https://github.com/IrineSistiana/mosdns) v5.3.4，GPL-3.0。
  VelaDNS 构建自定义入口程序，并注册 supervisor、熔断器、决策指标、
  请求指标和 TCP 服务器插件；
- [Unbound](https://github.com/NLnetLabs/unbound)，BSD-3-Clause；
- [Loyalsoldier v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)，
  GPL-3.0；
- [Loyalsoldier clash-rules](https://github.com/Loyalsoldier/clash-rules)，
  GPL-3.0；
- [UPX](https://github.com/upx/upx) 在镜像构建阶段压缩 Go 可执行文件，
  最终运行镜像不包含独立的 UPX 程序；
- Alpine Linux 软件包，遵循各自的许可证。

MosDNS 源码版本和完整 Go 依赖图由 `go.mod`/`go.sum` 固定。域名规则通过
上游发布包校验和验证；CN CIDR 快照固定到指定提交，并使用记录的校验和验证。
