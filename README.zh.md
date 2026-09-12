# dsh-hidden-paths

[English](README.md) | 中文

一个 **DeepSeek Harness**（`dsh`）插件，用于阻止 AI agent 读取它本不该读取的内容：`.env` 文件、凭据存储、私钥，以及**任何你选择隐藏的文件夹或文件**——同时通过 agent 的文件工具、它的 **shell 命令**、它的搜索选择器和它的代码执行进行拦截。

## 为什么需要它

`dsh` 内置的权限体系是一个*沙箱模式*（`read-only` / `workspace-write` / `danger-full-access`）加上一套审批策略。它约束的是**写入**；**读取是不受限制的**。因此，agent 在你的项目中工作时，可以 `cat .env` 或打开 `~/.ssh/id_rsa`，除非有什么东西阻止它。

本插件就是这个"什么东西"。它是一个**策略守卫**，而不是内核沙箱（见 [威胁模型](#threat-model--read-this)）。

## 安装

```bash
dsh plugin --profile web add dsh-hidden-paths
```

以上就是安装的全部步骤。该包声明了 `dsh.bundle.patch`，因此 `dsh plugin add` 会安装它，**并**将其作为一个 profile 层激活，同时带上安全的默认配置：不隐藏任何内容、密钥名称规则生效、凭据脱敏开启。

重启一次 `dsh` 服务器，以便导入新模块。

## 隐藏一个文件夹或文件

bundle 已经插入了插件条目，因此请在你自己 profile 的 patch 层中，用**以 `id` 为目标的 override** 来修改它的设置：

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: dsh-hidden-paths
  config:
    hiddenPaths:
      - /home/you/private          # a folder: its whole subtree is protected
      - /etc/app/master.key        # or a single file
```

> 请**不要**为本插件添加 `insert` 块。bundle 层已经插入了该条目，而具有相同 `id` 的第二个 `insert` 是一个重复的 loader 条目：profile 将无法启动。请改为按 `id` 进行 override。

对于列出的每一个路径：

| 效果 | 细节 |
|---|---|
| 拒绝访问 | 读取**和**写入都会被拒绝，来自文件工具（`read`、`write`、`edit`、`glob`、`grep`、`read_image`）、shell 命令（`cat`、`ls`、`cp`、`rm` 等）、搜索选择器（`glob`/`grep` 的 `pattern`、`include`、`exclude`）以及通过 `run_code` 执行的代码 |
| 覆盖整个子树 | 如果它是一个文件夹，其中的所有内容都受到保护 |
| 隐藏名称 | 在结果中**名称**会被掩码为 `[hidden]`，因此 `ls`、`ls -l`、`glob` 或 `find` 也无法泄露它 |
| 解析符号链接 | 指向隐藏路径内部的链接会被解析并拒绝——包括目标叶子节点尚不存在的情况 |
| 优先于 allow 列表 | `allow` 条目永远无法重新打开你明确隐藏的路径 |
| 包含子 agent | 适用于整棵 agent 树中的每一个 agent，而不仅是根 agent |

## 两个层面

**第 1 层 —— 路径拒绝。** 通过 `ctx.tools.guard()` 注册，这是一个**单调**守卫，在可扩展的 `tools/pre-execute` 瀑布之后求值。返回的理由会在*工具主体运行之前*拒绝该调用，并且**之后的任何监听器都无法把该拒绝重新变回许可**。

**第 2 层 —— 结果过滤。** 通过 `prepend` 注册在 `tools/post-execute` 上，因此它是最外层的监听器，也是最终决定者。它 (a) 将隐藏路径的名称掩码为 `[hidden]`，并 (b) 在模型看到这些值之前将形似凭据的值脱敏为 `[redacted:kind]`——因为一个密钥可能存在于文件名毫无提示的文件中（`notes.txt`、一行日志、一个脚本）。

第 2 层**只**会脱敏**明确无误的 token 格式**：OpenAI/Anthropic 密钥、GitHub/GitLab token、Stripe 密钥、`AKIA…`、`xox…`、`AIza…`、npm/Hugging Face token、JWT，以及 PEM 私钥块。

## 默认受保护的内容

除 `hiddenPaths` 之外，以下名称无论出现在哪里都受到保护：

| 类别 | 规则 |
|---|---|
| Dotenv 文件 | `.env`、`.env.*`、`*.env`、`*.env.*`（备份与变体） |
| 凭据存储 | `.npmrc`、`.netrc`、`.pypirc`、`.git-credentials`、`.pgpass`、`.htpasswd`、`.dockercfg`、`credentials`、`credentials.{json,yaml,yml,txt}`、`.credentials*`、`*service-account*.json` |
| 密钥 | `secrets`、`secrets.{json,yaml,yml,txt}`、`.secrets*`、`token.txt`、`tokens.txt`、`api-keys.txt`、`api_keys.txt` |
| 私钥 | `id_rsa*`、`id_ed25519*`、`id_ecdsa*`、`id_dsa*`、`*.pem`、`*.key`、`*.ppk`、`*.p12`、`*.pfx`、`*.jks`、`*.keystore`、`*.kdbx` |
| 基础设施变量 | `*.tfvars`、`*.tfvars.json` |
| 整个目录 | `.ssh`、`.aws`、`.gnupg`、`.kube`、`.docker`、`.secret-guard`、`secrets`、`.secrets`、`credentials` |

示例与模板文件（`.env.example`、`.env.sample`、`.env.template`、`.env.dist`、`.env.default`、`.env.test`）保持**可读**。

这些规则刻意保持**精确**，而不是 `*secret*`：宽泛的 glob 也会拦截普通源文件，例如 `secrets.ts`、`credentials-manager.py` 或 `tokenizer.py`。

## 配置

```yaml
- id: dsh-hidden-paths
  config:
    hiddenPaths: []           # ABSOLUTE paths (folders or files) to hide
    guardRoots: []            # legacy alias of hiddenPaths, still accepted
    extraNameRules: []        # extra basename globs, e.g. "*.vault"
    extraDirSegments: []      # extra directory names protected anywhere
    allow: []                 # exceptions; never re-opens a hiddenPath
    maskResults: true         # layer 2: credential redaction
    hidePathsInResults: true  # layer 2: also mask hidden path names
    maskNotice: true          # add a notice line when something was hidden
```

配置写错不可能悄悄让守卫失效：

- 在本应是数组的位置写了一个**字符串**时，会被读取为你本意的那一个条目（过去它会被拆分成单个字符，结果什么都没保护）；
- **相对路径**会相对于进程 cwd 解析，并记录一条警告；
- `hiddenPaths: ["/"]` 确实会隐藏一切，并通过一条警告说明这一点；
- 如果配置完全无法读取，插件会**拒绝每一次工具调用**并记录原因，而不是失败时默认放行。

## 设计说明：不损坏内容

一个激进的脱敏器比没有更糟。有三条规则确保本插件是安全的：

- 凭据模式永远不会匹配 `api_key = ...` 这样的赋值形态，因为那会在普通源代码（`const api_key = process.env.API_KEY`）上触发，并把一个可能被写回的损坏文件交给模型。
- 隐藏**名称**只会在它确实是一个路径（`/folder/x`、`folder/x`）或一行目录列表时被替换——绝不会作为句子中的一个词或 JSON 键被替换。隐藏一个名为 `data` 的文件夹，你在别处读到的 JSON 主体 `{"data": 1}` 不会被改动。
- 绝对路径的匹配是**按边界锚定的**：隐藏 `/srv/vault` 不会改写与之无关的 `/srv/vaulted/x`。

这三条都由专门的测试来保证。

## 威胁模型 —— 请阅读

**这是协作运行时上的一道策略守卫，而不是内核边界。** 它能阻止误操作、被 prompt 注入的"请 `cat` 我的 `.env`"，以及日常的越界行为。它**不能**阻止有决心的对手，原因如下：

- shell 分析是文本层面的：`cat "$SOMEVAR"`、`python -c '...'`、`find -name '*.env' -exec cat {} +`、`base64`、`env`/`printenv`、`/proc`、硬链接，或者读取一个已经打开的文件描述符，都能在不写出受保护路径的情况下触达同样的字节；
- 跨引号边界拆分一个**裸**名称（`"sec"rets`）不会被捕获——引号内的片段会被拼接，但来自引号区间内部的词会被视为普通文本，因此 `git commit -m "update .env"` 不会被拦截。带有路径分隔符或以点开头的名称不受影响；
- **`run_code` 会以 Node 的完整 API 执行任意代码。** 只有其文本中字面写出的路径才会被捕获，因此它仍然是一条真实的绕过途径；
- **默认名称规则从不解析符号链接**——只有配置的 `hiddenPaths` 才会解析，因此一个名称无害但指向密钥的符号链接不会被捕获；
- 第 2 层识别的是*形状*，而不是*含义*：以不常见格式出现的凭据会被放过；
- 凡是 agent 能读取的内容，它也能复制到别处。

守卫也会偏向拦截：一个展开后*可能*触达受保护名称的 glob（`cat .*`、`/srv/*/note.txt`、`ls se*`）即使无害也会被拒绝。请把这个 glob 收窄，或添加一条 `allow` 条目。

互补的防御手段：把真正关键的密钥放在 agent 工作区**之外**，用与文件属主不同的用户来运行 `dsh`，或者限制整个进程（container、seccomp、Landlock）。

## 开发

```bash
git clone https://github.com/Gabrip780/dsh-hidden-paths.git
cd dsh-hidden-paths
node test.js
```

零运行时依赖 —— 仅使用 Node 内置模块（`node:path`、`node:os`、`node:fs`）。唯一的文件系统调用是针对一个守卫本就在判定的路径执行 `realpathSync`：只读取元数据，绝不读取文件内容。无网络、不创建进程、不使用 `eval`。

`node test.js` 会打印一张 62 个用例的决策表，外加配置、隐藏路径、脱敏、插件接线以及审计后回归等断言分组——总共 93 行 `PASS`，并且任何失败都会以非零状态退出。该套件同时断言**两个方向**：哪些必须被拒绝，哪些必须保持允许。一个拦截过多的守卫和一个拦截不足的守卫同样是有问题的。

## 审查过程

在首次发布之前，本插件由五位独立的对抗性审查者（一位 bug 审计员、一位深度代码审查者、一位 0-day 猎手、一对红/蓝队成员，以及一位横向思维审查者）外加一位文档交叉核验者进行了审计。该审查发现了十二个真实缺陷——通过 shell `workdir` 的绕过、未被扫描的 `grep`/`glob` 选择器、方括号展开与裸 glob 规避、被引号包裹的裸名称、一个会悄悄让守卫失效的配置笔误、结果过滤中对相邻路径的破坏、一个越过了隐藏路径的 allow 列表，以及一个二次方复杂度的 regex——所有这些都已在此修复，并由回归测试覆盖。

## 生态

`dsh` 采用 MIT 许可，其 [CONTRIBUTING 指南](https://github.com/deepseek-ai/deepseek-harness/blob/master/CONTRIBUTING.md) 欢迎社区插件，并请作者添加 [`dsh-plugin`](https://github.com/topics/dsh-plugin) 话题以便被发现。本插件是在审计了社区中解决同一问题的各类守卫之后从零编写的；它与它们之间不共享任何代码。欢迎通过 [GitHub Discussions](https://github.com/deepseek-ai/deepseek-harness/discussions) 提供反馈。

## 许可

MIT
