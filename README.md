# Jupyter Server 内容服务

本项目提供服务端内容、目录、检查点、会话和鉴权接口。生产源码位于 `jupyter_server/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install --break-system-packages --no-build-isolation -e '.[test]'`

## 测试

`python3 -m pytest -q`

## 构建

`python3 -m compileall -q jupyter_server`

`python3 -m build --wheel --no-isolation`

## 使用

内容管理器可在本地目录上执行保存、复制、改名、删除和检查点操作，HTTP 处理器提供对应服务端接口。

## 可委托短期授权（`jupyter_server.auth.delegation`）

`DelegationAuthority` 为外部审阅者等临时访问签发可转授的短期授权，避免发放整站长
期令牌：

- **只收窄的转授**：每次转授只能缩减路径前缀、操作（`read`/`download`/`write`）、
  受众与剩余派生深度；后代不得晚于祖先过期，整站通配权限只允许停留在根。
- **级联撤销**：撤销链上任一节点即令全部后代立即失效，无需枚举派生凭证；重复撤销
  幂等。
- **在途操作一致规则**：只读下载在开始时取得持久化租约，撤销/过期后在可配置宽限期
  （`download_grace`，设为 0 立即切断）内完成；写操作在提交点重新全量校验，不享
  宽限。
- **轮换与重启**：每跳按密钥代次（`kid`）HMAC 签名，轮换保留旧代次可验证旧链；
  密钥环、签发索引、撤销集与租约落盘并逐条 HMAC 密封，服务重启后仍能验证完整授权
  链并检测状态篡改。
- **审计脱敏**：审计事件与面向部分授权审阅者的查询只暴露路径的 SHA-256 摘要
  （`redact_paths`），不泄露未获授权的路径名称。

相关回归测试见 `tests/auth/test_delegation.py`。

