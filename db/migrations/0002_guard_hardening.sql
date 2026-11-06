-- 0002: 审批门默认规则加固
--
-- 背景：0001 的默认 deny 规则主要面向 Unix（rm -rf / mkfs / shutdown），
-- 但 worker 在 Windows 上以 PowerShell 执行命令，Remove-Item -Recurse、
-- del /f /s、format、diskpart、reg delete、vssadmin delete 等破坏性操作未被覆盖。
-- 一旦 LLM 被诱导（或幻觉）执行这些命令，可能损坏运行主机。
--
-- 本迁移幂等：先按已知名字清理，再插入；已有库重启即生效。

DELETE FROM intercept_rules
 WHERE name IN (
   'deny-win-recursive-delete',
   'deny-format-disk',
   'deny-registry-delete',
   'deny-stop-restart-computer',
   'deny-backup-delete',
   'deny-remote-script-download',
   'deny-encoded-command',
   'deny-history-clear',
   'deny-sudo-elevation-spray'
 );

INSERT INTO intercept_rules (name, match_target, match_type, pattern, action, priority) VALUES
  -- Windows 递归/强制删除（保留单文件删除，避免过度封锁普通清理）
  ('deny-win-recursive-delete',   'tool_input', 'regex',
     '(?i)\b(remove-item|rmdir|rd|del|erase)\b[^|;&\n]*(\s-(recurse|force|r)\b|/[sf]\b)',
     'deny', 1),
  -- 格式化 / 分区 / 清盘
  ('deny-format-disk',            'tool_input', 'regex',
     '(?i)\b(format(-volume|\.com)?\s+[a-z]:|diskpart|clear-disk)',
     'deny', 1),
  -- 注册表写入/删除/加载（持久化/破坏常用）
  ('deny-registry-delete',        'tool_input', 'regex',
     '(?i)\breg(\.exe)?\s+(delete|add|load)\b',
     'deny', 1),
  -- 关机 / 重启
  ('deny-stop-restart-computer',  'tool_input', 'regex',
     '(?i)\b(stop-computer|restart-computer)\b',
     'deny', 1),
  -- 删除卷影/备份（勒索/反取证常用）
  ('deny-backup-delete',          'tool_input', 'regex',
     '(?i)\b(vssadmin|wbadmin)\b[^|;&\n]*\bdelete\b',
     'deny', 1),
  -- 远程脚本下载执行（dropper）。正常探测请用 curl.exe 下载后自行分析
  ('deny-remote-script-download', 'tool_input', 'regex',
     '(?i)\b(downloadstring|downloadfile|net\.webclient)\b',
     'deny', 1),
  -- PowerShell 编码命令（常用于隐藏恶意载荷）
  ('deny-encoded-command',        'tool_input', 'regex',
     '(?i)\b(powershell|pwsh)\b[^\n]*\s-(e|ec|enc|encodedcommand)\b',
     'deny', 1),
  -- 清空命令历史（反取证）
  ('deny-history-clear',          'tool_input', 'regex',
     '(?i)\b(clear-history|history\s+-c|set\s+history\s+-\d+)\b',
     'deny', 1),
  -- 批量提权/口令喷洒（对主机或目标都可能造成伤害）
  ('deny-sudo-elevation-spray',   'tool_input', 'regex',
     '(?i)\b(sudo\s+-[is]|su\s+-c)\b',
     'deny', 1)
ON CONFLICT DO NOTHING;
