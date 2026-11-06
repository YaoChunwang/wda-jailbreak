# wda-jailbreak —— 越狱 iOS 上跑通完整 WebDriverAgent UI 自动化（iPhone SE 1 / iOS 15.8.8 实测）

用真实的 Apple UI 测试栈远程驱动一台**越狱** iPhone：
WebDriverAgent + XCTestCore + XCUIAutomation + testmanagerd，
HTTP 端口直接输出实时 XCUI 元素树。不需要模拟器、不需要 Xcode、不需要开发者签名。

```
GET http://<device>:8100/source
→ <?xml version="1.0"?><XCUIElementTypeApplication …>…232 个真实元素…
   蜂窝网络 / 中国联通 / 12:38 / 电池电量：100% …
```

[English](README.md) | 简体中文

## 为什么会有这个仓库

在越狱设备上"没有 Xcode 跑 WebDriverAgent"听起来应该水到渠成，实际上不是。
iOS 15.8 的 XCTest 自动化栈有**五道互相独立的门**，每道门报出来的错都长得毫不相干：

1. 每次 AX 调用都 `kAXErrorAPIDisabled`
2. 自动化会话 `Timed out waiting for target to check in.`
3. `No bundle at path /Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework`
4. 每次查询解析都 `Application … is not running`
5. 一堆 `0x8badf00d` 看门狗：10 秒、19.7 秒连环杀

本仓库记录了五道门**真正的钥匙**，并开源了把整条链跑通的自制代码（ObjC 垫片）。

## 架构

```
┌─────────────────────────┐   HTTP :8100   ┌──────────────────────────────┐
│  客户端 (Appium / curl)  │──────────────▶│ WebDriverAgentRunner          │
└─────────────────────────┘               │  (Facebook WebDriverAgent，   │
                                          │   自签 + TrollStore 保活)     │
                                          ├──────────────────────────────┤
                                          │ objc_shim.dylib               │
                                          │  (本仓库，替换 libobjc +       │
                                          │   拦截 exit)                  │
                                          └──────────┬───────────────────┘
                                                     │ XPC / 自动化会话
                                          ┌──────────▼───────────────────┐
                                          │ testmanagerd                  │
                                          │  (Apple 二进制，取自 DDI，     │
                                          │   用完整 Apple 资格集重签)     │
                                          └──────────┬───────────────────┘
                                                     │ AX (MIG)
                                          ┌──────────▼───────────────────┐
                                          │ AccessibilityUIServer / SB    │
                                          │  = 设备上正在显示的真实 UI     │
                                          └──────────────────────────────┘
```

## 五把钥匙

### 1. `com.apple.accessibility.api`
`AXDisableAccessibilityOnTermination` 等调用全部 `kAXErrorAPIDisabled`，
根因是**调用方**（testmanagerd）签名里缺 `com.apple.accessibility.api`。
从 Apple 原装二进制导出完整资格集（`ldid -e`）后全量重签——见
`docs/testmanagerd_entitlements.plist`。另外 Accessibility 偏好设置里的
`AutomationEnabled` 等键必须**抢在 cfprefsd 吞回去之前**写好并验证。

### 2. 签到通知
`requestAutomationSessionForTestTargetWithPID:` 会一直等
`com.apple.dt.xctestd.availability.<pid>` 通知。垫片用 `notify_post` 冒充目标代发。
注意：pid 必须是 SpringBoard 的**真实 pid**（每次重启都会变，要在运行时解析）。

### 3. `preferredBackendPath`
守护会从 `/Developer/Library/PrivateFrameworks/…` 动态装载
`XCTAutomationSupport.framework`——没有挂 DDI 时这个路径根本不存在。
`requestAutomationSessionForTestTargetWithPID:preferredBackendPath:reply:` 的
第二个参数可以覆盖装载路径，指向你自己放的框架副本（从同一个 DDI 提取）。

### 4. `processID` → `accessibilityElement`（最后一把钥匙）
每次查询解析都走 `-[XCUIElementQuery backingQueryWithError:]`，当 app 的
`accessibilityElement` 为 nil 时直接报 `Application … is not running`。
而这个元素由进程的 `processID` 生成（pid = 0 ⇒ 元素 = nil）。反汇编出的链条：

```
XCUIApplication.accessibilityElement
  → XCUIApplicationImpl.accessibilityElement      (ivar 0x20)
    → XCUIApplicationProcess.accessibilityElement  (需要 processID ≠ 0)
```

所以：建进程 → `setProcessID:<真实 pid>` **有且只有一次**
（setter 断言只允许 0→N 或 N→0），真实 AX 元素——也就是 SpringBoard 的
活 UI——就出现了。

### 5. 三个看门狗
| 看门狗 | 时限 | 破法 |
|---|---|---|
| 进程启动 | 20 秒 | 主线程跑 `UIApplicationMain` |
| scene-create | 19.7 秒 | `didFinishLaunching` 最先建 `UIWindow`，重活全挪后台线程 |
| scene-update | 10 秒 | `_XCTSetXPCRequestTimeout(7.0)`，XPC 等待抢在看门狗前醒来 |

另外：`-[XCUIApplicationProcess waitForQuiescenceIncludingAnimationsIdle:]`
在没有测试上下文时抛 `Cannot pass nil activity`——swizzle 成空操作即可；
`configuredForUITesting` 必须返回 YES，否则 `commonInit` 直接断言。

## 仓库内容

| 路径 | 内容 |
|---|---|
| `src/objc_shim.c` | 完整垫片（最终 168 版迭代）：libobjc 透传、spec 应答钩子、进程/impl 接线、会话安装、状态钉死、喂食线程、看门狗规避。头部注释标出每个机制 |
| `src/wda_entitlements.plist` | WDA 主程序 + 垫片的资格（`platform-application`、`com.apple.accessibility.api` 等） |
| `docs/testmanagerd_entitlements.plist` | 从 Apple testmanagerd 导出的资格集（照这个重签） |
| `docs/TECHNICAL.md` | 深挖：反汇编笔记、对象图、reply block ABI 陷阱（英文） |
| `scripts/build.sh` | 构建垫片 |
| `scripts/deploy.sh` | 向设备部署 runner + 垫片 + 守护 |

## 安装（概要）

前置：越狱设备（此处 palera1n rootless）、TrollStore（保活启动）、OpenSSH、
`ldid`、以及目标机对应的 DDI（15.5 的 DeveloperDiskImage 可用于 15.8），
从中取 `testmanagerd` + `XCTestCore.framework` + `XCUIAutomation.framework`
+ `XCTAutomationSupport.framework`。

1. 构建安装 WebDriverAgentRunner（上游
   [facebookarchive/WebDriverAgent](https://github.com/facebookarchive/WebDriverAgent)），
   用 `src/wda_entitlements.plist` 自签，注册进 TrollStore 拿启动权。
2. `scripts/build.sh` 产出 `objc_shim.dylib`，同样资格签名，放到
   `/var/jb/objc_shim.dylib`（它 re-export libobjc，由越狱的 objc 替换钩子接管）。
3. 把 DDI 里的 `testmanagerd` 部署到 `/var/jb/usr/libexec/testmanagerd`，
   用 `docs/testmanagerd_entitlements.plist` 重签，用 LaunchDaemon 起（UserName mobile）。
4. 拷 `XCTAutomationSupport.framework` 到 `/var/jb/usr/lib/xctfw/`——垫片把这个
   路径作为 `preferredBackendPath` 传给守护。
5. `scripts/deploy.sh` + `uiopen` 启动 runner，然后
   `curl http://<device>:8100/source`。

## 法务

垫片与脚本使用 MIT 协议。`testmanagerd`、`XCTestCore`、`XCUIAutomation`、
`XCTAutomationSupport` 是 Apple 二进制——**不包含在本仓库**，请从你自己设备的
DDI 提取。本项目仅用于对自己拥有的设备做研究与个人自动化。
相关技术逆向了 Apple 私有 API，Apple 不提供任何支持。

## 当前状态

iPhone SE 1（iPhone8,4）、iOS 15.8.8（19H422）、palera1n rootless + TrollStore
实测：`/source` 可重复、稳定地输出 SpringBoard 实时元素树（232 个元素）。
点按/滑动端点建立在同一棵元素树上（同一套 WDA 上游），本仓库未实测——欢迎 PR。
