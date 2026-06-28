# Javis · 模型真偽公開審計 (Public Model-Authenticity Audit)

> 公開頁：**https://javisbot-service.github.io/javis-transparency/**

本仓库公开 Javis 中转站对在售模型做**模型替换（掉包）审计**的全部内容——代码、运行记录、结果。目的：把"模型真不真"从"相信我"变成**"你自己查、第三方查"**。

## 为什么这是可信的

| 你可能质疑 | 你能自己核查 |
|---|---|
| "代码是不是这份?" | 仓库里 [`audit/probe_public.py`](audit/probe_public.py)，带完整 commit 历史 |
| "真跑了吗?" | [**Actions 运行日志**](../../actions) —— 每次定时运行的原始输出公开可见 |
| "结果是不是手改的?" | 结果由 `github-actions[bot]` 提交（非站长账号），git 历史哈希链防篡改、force-push 可见 |
| "页面是不是另做的?" | 页面由 GitHub Pages 从本仓库 `docs/` 直接生成，不经 Javis 服务器 |

**执行不在 Javis 的服务器上**，而在 GitHub 的机器上跑公开代码——这是可信度的核心。

## 检测方法（实现自已发表研究，非自创）

- Cai, Shi, Zhao, Song, *Are You Getting What You Pay For? Auditing Model Substitution in LLM APIs*, [arXiv:2504.04715](https://arxiv.org/abs/2504.04715)
- Zhang et al. (CISPA), *Real Money, Fake Models: Deceptive Model Claims in Shadow APIs*, [arXiv:2603.01919](https://arxiv.org/abs/2603.01919) — 发现 45.83% 影子 API 未通过模型身份验证
- Zhu et al., *Auditing Black-Box LLM APIs with a Rank-Based Uniformity Test*, [arXiv:2506.06975](https://arxiv.org/abs/2506.06975)
- Lin et al., *Behavioral Consistency and Transparency Analysis on LLM API Gateways* (IMC'26), [arXiv:2604.21083](https://arxiv.org/abs/2604.21083)

## 自己验证（不必信我们）

公开页列出确定性探针（`temperature=0`）与一段可复制的 `curl`。用你自己的 key 对 `https://api.javis.bot` 跑，比对补全是否一致、响应 `model` 字段是否为宣称模型。审计用的 endpoint 与你日常呼叫的是同一个。

## 局限（诚实声明）

本审计为**概率性一致性检测，非密码学证明**。理论上提供方可对已知审计来源返真、对真实流量掉包（见 arXiv:2506.06975）——这是所有黑盒审计的共同局限。我们以"你可复现"缓解。

## 结构

```
audit/probe_public.py   纯标准库探针：探测→判定→写结果（无密钥、无内网信息）
audit/probes.json       公开探针集
audit/config.json       公开配置
audit/baselines/        版本化参考基线（由 capture-baseline 生成）
docs/index.html         透明页（GitHub Pages 托管）
docs/data/history.json  审计历史（由 bot 提交）
.github/workflows/audit.yml  每 6h 定时 + 手动触发
```

许可：MIT。
