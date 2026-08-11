# SchatPhone 素材治理与迁移手册

本手册用于把 SchatPhone 的大体积母版素材迁移到自建 CloudFlare ImgBed，同时保留可验证、可回滚的本地清单。迁移期间不要直接删除远端文件，也不要改写 SchatPhone Git 历史。

## 1. 部署前安全基线

生产环境必须配置以下变量：

- `BASIC_USER`：管理员用户名。
- `BASIC_PASS`：管理员密码，使用随机生成的高强度值。
- `AUTH_CODE`：普通用户访问密码，使用与管理员密码不同的值。
- `AUTH_ALLOW_ANONYMOUS=false`：保持默认拒绝匿名访问。只有临时兼容旧站时才可显式设为 `true`。
- `PROTECTED_FILE_PREFIXES=schatphone-source`：要求该目录的下载也必须通过认证。

部署前还必须轮换当前 Hugging Face Token。旧部署曾允许匿名读取上传配置，因此旧 Token 应按已经暴露处理：先在 Hugging Face 创建新 Token并更新 Cloudflare，再撤销旧 Token。

禁止把密码、Hugging Face Token、Cloudflare API Key 或迁移 API Token 写入仓库、清单或命令历史。使用 Cloudflare Secret 或部署平台的加密变量保存它们。

设置备份响应会标记 `secretsExcluded=true`，并排除认证信息、渠道密钥和 API Token 记录。恢复备份后需要从加密变量或密码管理器重新配置这些密钥。

## 2. 迁移令牌

通过图床管理端创建一次性迁移 Token，只授予：

- `upload`
- `list`

不要授予 `delete` 或 `manage`。Token 只在创建响应中返回一次，服务端仅保存 SHA-256 哈希。迁移完成并复核后立即撤销该 Token。

## 3. 母版上传契约

受保护素材统一放到 `schatphone-source/`，请求必须满足：

- `uploadNameType=origin`，保留原始文件名。
- 表单字段 `sha256` 为本地文件的 SHA-256 小写十六进制值。
- `Authorization: Bearer <migration-token>`。
- 同一文件 ID 已存在时返回 `409`，不得自动重命名或覆盖。

成功响应必须记录服务端返回的 `fileId` 和 `sha256`。任何缺少哈希、哈希不一致或重名冲突都应停止当前批次。

## 4. 分批迁移顺序

1. 先用不含敏感内容的小文件做上传、列出和下载冒烟测试。
2. 为 `output/imagegen` 生成清单，至少包含相对路径、字节数、本地 SHA-256、远端 `fileId` 和远端 URL。
3. 小批量上传，逐文件下载并重新计算 SHA-256；只有本地、上传响应和下载结果三者一致才标记完成。
4. 完成整批复核后，在 SchatPhone 中把运行时引用改为远端 URL，并保留清单。
5. 验证构建、测试和线上访问后，才停止跟踪已迁移文件。先保留本地副本或独立备份。
6. Git 历史重写是独立的高风险阶段，必须另行确认、备份并协调所有克隆，不属于首次迁移。

## 5. 回滚原则

- 应用引用切换前，远端上传失败只需停止批次，不影响现有项目。
- 引用切换后如有异常，恢复到上一提交中的本地路径；不要删除图床副本。
- 只有在远端校验、应用验证和备份都完成后，才考虑清理本地受控大文件。
- 任何删除操作都必须从已复核清单生成精确目标，不使用目录级通配删除。

## 6. 验收门槛

- 未登录访问 `/api/manage/*`、`/upload` 和 `/file/schatphone-source/*` 返回 `401`。
- 配置读取接口不返回任何明文密钥或 API Token 记录。
- 迁移 Token 可上传和列出，但不能删除或修改系统配置。
- 受保护上传缺少或错误 SHA-256 时失败，同名上传返回 `409`。
- 下载文件 SHA-256 与本地清单完全一致。
