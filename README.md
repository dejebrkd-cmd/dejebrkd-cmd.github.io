# Meridian Security Research — site

Static site for GitHub Pages (Jekyll). No build step: this directory is the
repository root. Upload as-is.

## 部署（4 步）

**① 建仓库**

仓库名必须是：

```
<你的 GitHub 用户名>.github.io
```

举例：GitHub 用户名是 `zhangsan`，仓库名就是 `zhangsan.github.io`。
名字必须完全一致，否则 GitHub Pages 不会启用。

**② 上传这些文件**

```bash
git init
git add .
git commit -m "init"
git branch -M main
git remote add origin git@github.com:<你的用户名>/<你的用户名>.github.io.git
git push -u origin main
```

不想用命令行：在仓库页面点 `Add file → Upload files`，把整个目录拖进去。

**③ 打开 Pages**

```
仓库 Settings → Pages
  → Source: Deploy from a branch
  → Branch: main / (root)
  → Save
```

**④ 等 60 秒，访问**

```
https://<你的用户名>.github.io
```

## 目录结构

```
_config.yml                              站点配置（通常不用改）
index.md                                 首页：研究方向 / 三篇 writeup / 边界声明 / 联系
disclosure.md                            90 天协同披露政策
SECURITY.md                              漏洞报告渠道
README.md                                这个文件，不用上传也行
writeups/
  ebpf-verifier-pointer-arithmetic.md    Linux 内核 / eBPF 分析
  doh-c2-detection.md                    网络检测工程
  lsass-access-sigma.md                  Windows 检测 + 规则测试
```

## 唯一可能需要改的地方

`_config.yml` 里的 `baseurl` 和 `url`：

- 仓库名是 `<用户名>.github.io`（**用户主页**）→ **留空，不要改**
- 仓库名是别的（**项目页**，网址变成 `<用户名>.github.io/<仓库名>`）→ 填上仓库名

默认已经是留空状态，用户主页直接就能用。

## 之后可以加

```
tools/      你自己写的脚本，每个带 README
```

`SECURITY.md` 里现在是「通过 GitHub Issue 联系」，不需要邮箱。想加邮箱就自己补一行。
