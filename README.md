# RouteVulScan-modify
Burpsuite - Route Vulnerable scanning  递归式被动检测脆弱路径的burp插件

***

## 介绍

RouteVulScan是使用java语言基于burpsuite api开发的可以递归检测脆弱路径的burp插件。

插件可以通过被动扫描的方式，递归对每一层路径进行路径探测，并通过设定好的正则表达式匹配响应包的关键字，展示在VulDisplay界面。可以自定义相关路径、匹配信息、与漏洞名称等。

插件重点是那些简单而有害的漏洞。这些漏洞通常不是固定路径，但可能位于路径的任何层。在这种情况下，非常容易忽视这些漏洞，而如果使用路径爆破，则非常耗时和麻烦。

所以插件主打是发送数量小、准确的payload，尽可能覆盖面广的探测一些容易忽略的漏洞。


## 使用

### 构建(开发者)

项目使用 Maven 构建,要求 JDK 21+(对齐 Burp 自 2024.2.1 起的最低内置 JRE)。

```bash
mvn clean package
# 产物:target/RouteVulScan-1.6.0.jar
```

运行单元测试:

```bash
mvn clean test
```

### 装载插件

装载插件：``` Extender - Extensions - Add - Select File - Next ```

初次装载插件会在burpsuite当前目录下生成Config_yaml.yaml配置文件，用来储存匹配规则，该文件默认在当前burp目录下。

插件支持在线更新，点击Update按钮更新追加最新规则。部分网络需要挂代理，在线更新使用的是burp网络，所以可以直接配置burp的顶级代理。

## 功能介绍

* 被动扫描，使用Burpsuite IScannerCheck接口，在流量初次流经burp时进行扫描，重复流量不会进行扫描。

  * 对流经流量的每一层路径进行规则探测，并进行正则匹配，符合规则则展示在VulDisplay界面
  * 如https://www.baidu.com/aaa/bbb，则会对/、/aaa/、/aaa/bbb/ 分别进行探测，如果存在点后缀，则会跳过。

* 使用线程池增加扫描速度，默认线程10，可自行调节（线程个数最多与规则个数相等，多了也没用）

* Start按钮，插件主开关，默认关闭

* DomainScan按钮，开启后如果host为域名，则将子域和主域当作第一层路径进行扫描，默认关闭。

* Head按钮，携带原始的请求头，默认关闭

* Bypass按钮，不符合预期时将配置文件中的bypass字符添加到路径中重新扫描，默认关闭

* Filter_Host 输入框，被动扫描的 host 白名单过滤器，只对 host 匹配该输入的流量进行扫描。`*` 代表匹配全部（默认），如 `*.baidu.com` 只扫描百度系域名。

  * **仅对被动扫描生效**。右键「Send To RouteVulScan」主动扫描不走此过滤，会直接扫描站点地图中同 host 的所有历史路径。
  * **输入按通配符转正则后部分匹配**（`Pattern.find`）：`.` 转义为字面量 `\.`，`*` 转换为 `.*?`。即输入会被当成"包含匹配"而非"精确匹配"。

    | 输入 | 转换后的正则 | 匹配的 host |
    |------|------------|------------|
    | `*`（默认） | `.*?` | 所有 host |
    | `*.baidu.com` | `.*?\.baidu\.com` | `www.baidu.com`、`pan.baidu.com`… |
    | `baidu.com` | `baidu\.com` | 任何包含 `baidu.com` 的 host |
    | `192.168.1.*` | `192\.168\.1\..*?` | `192.168.1.1` ~ `192.168.1.254` |
    | `*test*` | `.*?test.*?` | 任何含 `test` 的 host |

  * **注意**：因采用部分匹配，输入 `baidu` 也会命中 `evilbaidu.com`、`baidu.com.evil.com` 这类包含子串的 host。若需限定子域，请写成 `.*?\.baidu\.com`。

* VulDisplay界面右键可删除选中的行，或全部删除

* 右键请求可选择将当前请求发送到插件进行主动扫描，插件会将站点地图中，与当前请求使用一样host的历史路径全部进行扫描

* 规则中可使用特殊标记获取原始请求或响应中的信息，用作请求的路径或正则。

  ```
  请求相关：
    {{request.head.*}}	-- 获取请求中head的各项，如获取cookie，{{request.head.cookie}}
    {{request.head.host.main}}	-- 获取host的根域名，如www.baidu.com:443，则获取baidu.com
    {{request.head.host.name}}	-- 获取域名，如www.baidu.com:443，则获取baidu
    {{request.method}}	-- 获取请求的方法，如GET/POST
    {{request.path}}	-- 获取请求的路径，如/aaa/bbb，则获取aaa/bbb
    {{request.url}}	-- 获取完整请求url
    {{request.protocol}}	-- 获取请求的协议，如http/https
    {{request.port}}	-- 获取请求的端口号
  响应相关：
    {{response.head.*}}	-- 获取响应中head的各项，如获取server，{{response.head.server}}
    {{response.status}}	-- 获取响应的状态码
  ```

* 状态码一栏可指定范围，如 200-299,500-599,302 可使用逗号来指定多个范围或多个状态码。


### Config 面板控件清单

配置（Config）Tab 自上而下、从左到右共 9 组可交互控件：

| #   | 控件 | 作用 |
|-----|------|------|
| 1   | `Start` 按钮 | **插件总开关**，关闭时被动扫描直接返回空；点击后变 `Stop` + 绿底 |
| 2   | `Head_On` 按钮 | **携带原始请求头**扫描（鉴权场景必开，会复用 Cookie/Authorization）；点击变 `Head_Off` + 绿底 |
| 3   | `DomainScan_On` 按钮 | **域名扫描**，开启后把 host 的子域/主域也当路径层；点击变 `DomainScan_Off` + 绿底 |
| 4   | `Bypass_On` 按钮 | **Bypass 开关**，规则首轮没命中时用 `Bypass_List` 字符（如 `.`、`;`、`..;/`、`%2f`）插入路径重试 |
| 5   | `Filter_Host` 输入框 | **Host 过滤**，支持 `*` 通配，如 `*.baidu.com`，只扫匹配 host 的流量（详见上文） |
| 6   | `Yaml File Path` 只读文本框 | 显示当前规则文件路径（默认 `Burp目录/Config_yaml.yaml`），不可编辑 |
| 7   | `Update` 按钮 | **在线更新规则**，从 `raw.githubusercontent.com/F6JO/RouteVulScan/main/Config_yaml.yaml` 拉取并追加 |
| 8   | `Load Yaml` 按钮 | **重新加载本地规则文件**（手动改 yaml 后点一下生效） |
| 9   | `Thread Numbers` 数字选择器 | **扫描线程数**，范围 1–500，默认 10，步进 3 |

> 此外还有左侧的 `Add` / `Edit` / `Del` 三个规则编辑按钮，以及中间按规则 `type` 字段自动分组的 `ruleTabbedPane`（右键标题可删除分类，双击可重命名，末尾 `...` Tab 双击可新建分类）。


## 更新计划

* 2022-06-19 右键选择请求发送到插件扫描【✓】
* 2022-06-30 域名过滤【✓】
* 2022-06-19 UI界面增加数据包大小【✓】 
* 2022-06-22 VulDisplay界面添加删除功能【✓】
* 2022-06-30 插件功能开关【✓】
* 2022-06-30 带原始请求头访问【✓】
* 2022-06-30 可自定义post/get请求【✓】
* 2022-07-01 配置文件在线更新【✓】
* 2022-10-18 添加分类，提供可根据个人习惯对规则进行分类处理【✓】
* 2022-10-18 添加选择，每个规则设置为可选的形式，可自由选择想要的规则【✓】
* 2023-02-04 添加bypass规则，在正常请求不符合预期时，尝试在路径中插入bypass字符尝试绕过【✓】
* 2023-05-09 将匹配的state状态码改为可以设置范围【✓】
* 2023-05-09 添加类似模板语言的标记，可在Config中配置标记获取当前请求的各类信息并当作路径或正则【✓】
* 2024-03-07 展示面板加入排序，优化bypass功能【✓】
* 修改UI适配
* 2026-06-13 修复多项缺陷、解除 JDK 内部 API 耦合并移除 rt.jar、构建现代化(Gradle 9/JDK 21)、新增单元测试【✓】详见 [CHANGELOG.md](./CHANGELOG.md)
* 2026-06-14 安全加固与健壮性提升:
  - SnakeYAML 升级至 2.2 并启用 SafeConstructor(缓解 CVE-2022-1471,远程拉取的规则不再可触发任意类构造)【✓】
  - id 类型统一(新增 `safeParseId`,消除 ClassCastException/NumberFormatException)、模板标记数组越界守卫、状态码解析对非法值容错(`any`/`*` 匹配全部状态码)【✓】
  - `vulscan` 重型构造器拆分为 `scan()`,可读性与可测性提升【✓】
  - Java 字节码目标 1.8 → 21(对齐 Burp 自 2024.2.1 起的最低内置 JRE),消除全部 "源值/目标值 8 已过时" 编译警告【✓】
  - 单元测试扩充至 61 例(全绿)【✓】详见 [CHANGELOG.md](./CHANGELOG.md)
* 2026-06-14 UI 与文档优化:
  - 修复 Config 面板按钮/标签文字被遮挡(JButton 默认 margin 过大),统一压边并重排布局【✓】
  - README 补充 `Filter_Host` 过滤器使用说明(被动扫描专用、通配符转正则、部分匹配语义、用法对照表)【✓】

