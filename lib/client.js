/**
 * dsh-security-watch — browser half.
 *
 * Loaded by the Harness client module table as a lazy factory. React comes from
 * the table (`require('react')`); no bundler and no Harness Client package
 * imports, per the UI-plugin authoring rules.
 *
 * Data comes from the authenticated routes the host half registers:
 *   GET /api/security-watch/state
 *   GET /api/security-watch/deep-audit?plugin=<name>
 *
 * The popup is event-driven: it opens only for a plugin that actually mounted
 * after this page loaded (`trigger: "mount"`), which is exactly the
 * enable/install gesture. Historical pending items never pop up on their own;
 * the badge is the standing surface for those.
 */
window.__ModuleLoader__.load({
  id: 'dsh-security-watch',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const SEEN_KEY = 'dsh.security-watch.seen';
    const POLL_MS = 3000;

    const zh = /^zh/i.test(navigator.language || '');
    const T = (cn, en) => (zh ? cn : en);

    function markSeen(keys) {
      try {
        const seen = JSON.parse(localStorage.getItem(SEEN_KEY) || '{}');
        for (const k of keys) seen[k] = Date.now();
        localStorage.setItem(SEEN_KEY, JSON.stringify(seen));
      } catch {
        // Private mode: dismissal still works for this page via component state.
      }
    }

    const card = {
      position: 'fixed',
      right: 20,
      bottom: 84,
      width: 420,
      maxWidth: 'calc(100vw - 40px)',
      zIndex: 2147483000,
      background: 'var(--dsw-alias-bg-elevated, #fff)',
      color: 'var(--dsw-alias-text-primary, #111)',
      border: '1px solid var(--dsw-alias-border-base, rgba(0,0,0,0.12))',
      borderRadius: 12,
      boxShadow: '0 12px 32px rgba(0,0,0,0.18)',
      padding: 16,
      font: '13px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif',
    };

    const button = {
      padding: '6px 12px',
      borderRadius: 8,
      border: '1px solid var(--dsw-alias-border-base, rgba(0,0,0,0.18))',
      background: 'transparent',
      color: 'inherit',
      cursor: 'pointer',
      fontSize: 13,
    };

    function severityColor(verdict) {
      if (verdict === 'risk') return 'var(--dsw-alias-danger, #d33)';
      if (verdict === 'attention') return 'var(--dsw-alias-warning, #c80)';
      return 'var(--dsw-alias-success, #2a7)';
    }

    function summary(item) {
      const c = item.counts || {};
      let text;
      if (item.verdict === 'risk') {
        text = zh
          ? `发现 ${c.high} 项高危、${c.medium} 项中危。确认来源可信前，建议先禁用。`
          : `${c.high} high, ${c.medium} medium. Consider disabling until you trust the source.`;
      } else {
        text = zh ? `发现 ${c.medium} 项需要留意的模式。` : `${c.medium} pattern(s) worth a look.`;
      }
      if (item.incomplete === true || item.truncated === true) {
        text += zh
          ? ' 扫描不完整（有文件超限或不可读），可能漏报。'
          : ' Scan incomplete (size limits or unreadable files); findings may be missing.';
      }
      return text;
    }

    function Panel(props) {
      const { state, onDismiss, open, openedAt, dismissed } = props;
      const [expanded, setExpanded] = React.useState(false);
      const [busy, setBusy] = React.useState(undefined);
      const [notice, setNotice] = React.useState(undefined);
      const [confirming, setConfirming] = React.useState(false);
      const [trusting, setTrusting] = React.useState(false);

      const live = state.live || [];
      // Only work triggered by an enable gesture after this page loaded: a
      // bundle toggle (`enable`) or an actual mount. Bulk rescan triggers are
      // `sweep`/`boot` and only refresh the badge.
      const isEnable = (t) => t === 'enable' || t === 'mount';
      const scanning = live.filter(
        (x) => (x.status === 'queued' || x.status === 'scanning') && isEnable(x.trigger) && (x.startedAt || 0) >= openedAt,
      );
      const recent = live
        .filter(
          (x) =>
            x.status === 'done' &&
            isEnable(x.trigger) &&
            (x.finishedAt || 0) >= openedAt &&
            !dismissed.includes(`${x.plugin}@${x.finishedAt}`),
        )
        .sort((a, b) => (a.finishedAt || 0) - (b.finishedAt || 0));
      const head = recent.length > 0 ? recent[0] : undefined;
      const pending = state.pending || [];
      const item = open ? pending[0] : head !== undefined ? pending.find((p) => p.plugin === head.plugin) : undefined;
      // A newly enabled official bundle is skipped by the static rules; it
      // still gets a popup, with the LLM deep-audit choice.
      const skipped = item === undefined && head !== undefined && head.skipped === true ? head : undefined;
      // A clean scan also reports back, so "enable → result" is always visible.
      const passed = item === undefined && skipped === undefined && head !== undefined && head.verdict === 'ok' ? head : undefined;
      const showScanning = scanning.length > 0;
      const showEmpty = open && item === undefined && skipped === undefined && passed === undefined && !showScanning;
      const visible = showScanning || item !== undefined || skipped !== undefined || passed !== undefined || showEmpty;
      if (!visible) return null;

      const current = item;
      const liveKey = head !== undefined ? `${head.plugin}@${head.finishedAt}` : undefined;
      const keys = current && current.hash ? [`${current.plugin}@${current.hash}`] : [];
      const remaining = recent.length > 1 ? recent.length - 1 : 0;

      async function startDeepAudit() {
        const pluginName = current
          ? current.plugin
          : skipped !== undefined
            ? skipped.plugin
            : passed !== undefined
              ? passed.plugin
              : scanning[0].plugin;
        setBusy('deep');
        setNotice(undefined);
        try {
          const briefRes = await fetch(`/api/security-watch/deep-audit?plugin=${encodeURIComponent(pluginName)}`, {
            credentials: 'same-origin',
          });
          if (!briefRes.ok) throw new Error(`brief ${briefRes.status}`);
          const brief = await briefRes.json();
          const remote = props.ctx.remote;
          if (remote === undefined || remote.session === undefined) throw new Error('remote session API unavailable');
          const created = await remote.session.create({});
          if (!created || created.ok !== true) {
            const reason = created && created.error ? `${created.error.code}: ${created.error.message}` : 'unknown';
            throw new Error(`session.create failed (${reason})`);
          }
          const sessionId = created.value.sessionId;
          await remote.session.prompt({
            requestId: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
            sessionId,
            mode: 'queue',
            content: [{ type: 'text', text: brief.text }],
            clientTimeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          });
          setNotice(zh ? '已创建新会话并提交审计任务，请到侧栏打开该会话。' : 'New session created with the audit brief — open it from the sidebar.');
        } catch (error) {
          const remoteKeys = props.ctx && props.ctx.remote ? Object.keys(props.ctx.remote).filter((k) => !k.startsWith('$')).join(',') : 'none';
          const detail = error && error.message ? error.message : String(error);
          const diagnostic = `${detail} [remote: ${remoteKeys}]`;
          try {
            const res = await fetch(`/api/security-watch/deep-audit?plugin=${encodeURIComponent(pluginName)}`, { credentials: 'same-origin' });
            if (res.ok) {
              const brief = await res.json();
              await navigator.clipboard.writeText(brief.text);
              setNotice(zh ? `创建会话失败：${diagnostic}。任务书已复制，可手动新建会话后粘贴。` : `Could not create a session: ${diagnostic}. The brief was copied — start a new conversation and paste it.`);
            } else {
              setNotice(diagnostic);
            }
          } catch {
            setNotice(diagnostic);
          }
        } finally {
          setBusy(undefined);
        }
      }

      async function disablePlugin() {
        setBusy('disable');
        setNotice(undefined);
        try {
          const res = await fetch('/api/security-watch/disable', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ plugin: current.plugin }),
          });
          const answer = await res.json().catch(() => ({ ok: false, detail: `http ${res.status}` }));
          if (!answer.ok) throw new Error(answer.detail || 'refused');
          setNotice(zh ? `已关闭 ${current.plugin}。` : `${current.plugin} was disabled.`);
          onDismiss(keys, liveKey);
        } catch (error) {
          setNotice(zh ? `关闭失败：${String(error && error.message ? error.message : error)}` : `Disable failed: ${String(error && error.message ? error.message : error)}`);
        } finally {
          setBusy(undefined);
          setConfirming(false);
        }
      }

      async function trustPlugin() {
        setBusy('trust');
        setNotice(undefined);
        try {
          const res = await fetch('/api/security-watch/ignore', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ plugin: current.plugin, reason: 'false positive confirmed by a deep audit' }),
          });
          const answer = await res.json().catch(() => ({ ok: false, detail: `http ${res.status}` }));
          if (!answer.ok) throw new Error(answer.detail || 'refused');
          setNotice(zh ? `已信任 ${current.plugin}（仅此版本；产物变更后会重新审计）。` : `Trusted ${current.plugin} (this artifact only; a changed artifact is audited again).`);
          onDismiss(keys, liveKey);
        } catch (error) {
          setNotice(zh ? `信任失败：${String(error && error.message ? error.message : error)}` : `Trust failed: ${String(error && error.message ? error.message : error)}`);
        } finally {
          setBusy(undefined);
          setTrusting(false);
        }
      }

      const title = showScanning
        ? T('正在安全审计…', 'Running a security audit…')
        : item !== undefined
          ? T(`安全审计：${item.plugin}`, `Security audit: ${item.plugin}`)
          : skipped !== undefined
            ? T(`安全审计：${skipped.plugin}`, `Security audit: ${skipped.plugin}`)
            : passed !== undefined
              ? T(`安全审计：${passed.plugin}`, `Security audit: ${passed.plugin}`)
              : T('安全审计', 'Security audit');

      return h(
        'div',
        { style: card, role: 'dialog', 'aria-live': 'polite', 'aria-label': title },
        h(
          'div',
          { style: { display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'baseline' } },
          h('strong', { style: { fontSize: 14 } }, title),
          h(
            'button',
            {
              style: { ...button, border: 'none', padding: '0 4px', fontSize: 16, lineHeight: 1 },
              'aria-label': T('关闭', 'Close'),
              onClick: () => onDismiss(keys, liveKey),
            },
            '×',
          ),
        ),
        showScanning
          ? h(
              'div',
              { style: { marginTop: 8 } },
              T('正在扫描插件源码，结果会在完成后显示在这里。', 'Scanning the plugin source; the result will appear here.'),
              h('div', { style: { marginTop: 6, opacity: 0.7, fontSize: 12 } }, scanning.map((s) => s.plugin).join(', ')),
            )
          : skipped !== undefined
            ? h(
                'div',
                null,
                h(
                  'div',
                  { style: { marginTop: 8, color: 'var(--dsw-alias-warning, #c80)' } },
                  skipped.reason === 'unresolved'
                    ? T(
                        '未能定位该插件的安装目录，本次审计被跳过（可能安装尚未完成）。请到插件页把它关闭再开启以重试。',
                        'Could not locate the plugin installation, so this audit was skipped (the install may not have finished). Toggle the plugin off and on to retry.',
                      )
                    : skipped.reason === 'watchdog'
                      ? T(
                          '本次审计没能完成（超时保护已中止它）。请重新启用该插件以重试。',
                          'This audit did not finish (a timeout guard stopped it). Re-enable the plugin to retry.',
                        )
                      : T(
                          '这是官方包，静态规则默认跳过。硬编码规则未必覆盖全部风险，建议用 LLM 深入审计后再决定。',
                          'Official bundle: the static rules skip it by default. Hard-coded rules are not exhaustive — run an LLM deep audit before you decide.',
                        ),
                ),
                h(
                  'div',
                  { style: { marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' } },
                  skipped.reason === 'unresolved' || skipped.reason === 'watchdog'
                    ? null
                    : h(
                        'button',
                        { style: { ...button, borderColor: 'var(--dsw-alias-accent, #247bbf)', color: 'var(--dsw-alias-accent, #247bbf)' }, disabled: busy === 'deep', onClick: startDeepAudit },
                        busy === 'deep' ? T('处理中…', 'Working…') : T('用 LLM 深入审计', 'Deep audit with the LLM'),
                      ),
                  h('button', { style: button, onClick: () => onDismiss(keys, liveKey) }, T('稍后处理', 'Later')),
                ),
                remaining > 0
                  ? h('div', { style: { marginTop: 6, fontSize: 12, opacity: 0.7 } }, T(`另有 ${remaining} 个插件刚完成审计`, `${remaining} more audit result(s) queued`))
                  : null,
                notice ? h('div', { style: { marginTop: 8, fontSize: 12, opacity: 0.85 } }, notice) : null,
              )
            : passed !== undefined
              ? h(
                  'div',
                  null,
                  h(
                    'div',
                    { style: { marginTop: 8, color: 'var(--dsw-alias-success, #2a7)' } },
                    T('未发现已知风险模式。静态检测不代表完全安全。', 'No known risk patterns found. A heuristic scan is not a guarantee.'),
                  ),
                  h(
                    'div',
                    { style: { marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' } },
                    h(
                      'button',
                      { style: { ...button, borderColor: 'var(--dsw-alias-accent, #247bbf)', color: 'var(--dsw-alias-accent, #247bbf)' }, disabled: busy === 'deep', onClick: startDeepAudit },
                      busy === 'deep' ? T('处理中…', 'Working…') : T('用 LLM 深入审计', 'Deep audit with the LLM'),
                    ),
                    h('button', { style: button, onClick: () => onDismiss(keys, liveKey) }, T('关闭', 'Close')),
                  ),
                  remaining > 0
                    ? h('div', { style: { marginTop: 6, fontSize: 12, opacity: 0.7 } }, T(`另有 ${remaining} 个插件刚完成审计`, `${remaining} more audit result(s) queued`))
                    : null,
                  notice ? h('div', { style: { marginTop: 8, fontSize: 12, opacity: 0.85 } }, notice) : null,
                )
              : showEmpty
            ? h(
                'div',
                { style: { marginTop: 8 } },
                T('当前没有待处理的风险。', 'No pending risks right now.'),
                h('div', { style: { marginTop: 8, fontSize: 11, opacity: 0.55 } }, T('静态规则检测，不代表完全安全。', 'Heuristic scan; not a guarantee.')),
              )
            : h(
                'div',
                null,
                h('div', { style: { marginTop: 8, color: severityColor(current.verdict) } }, summary(current)),
                current.findings && current.findings.length > 0
                  ? h(
                      'div',
                      { style: { marginTop: 8 } },
                      h('button', { style: button, onClick: () => setExpanded(!expanded) }, expanded ? T('收起详情', 'Hide details') : T(`查看 ${current.findings.length} 条发现`, `Show ${current.findings.length} findings`)),
                      expanded
                        ? h(
                            'ul',
                            { style: { margin: '8px 0 0', paddingLeft: 18, fontSize: 12, opacity: 0.85, maxHeight: 160, overflow: 'auto' } },
                            current.findings.map((f, i) => h('li', { key: i }, `[${f.severity}] ${f.rule} ${f.file}:${f.line}`)),
                          )
                        : null,
                    )
                  : null,
                current.verdict === 'risk'
                  ? h(
                      'div',
                      { style: { marginTop: 8, fontSize: 12 } },
                      T('建议操作：关闭该插件；如需先确认安全性，可先做一次 LLM 深度审计。', 'Suggested: disable this plugin — or run an LLM deep audit first if you want a second opinion.'),
                      h('div', { style: { marginTop: 4 } }, h('code', { style: { fontSize: 11, opacity: 0.75 } }, `security_watch_disable({plugin:"${current.plugin}"})`)),
                    )
                  : null,
                h(
                  'div',
                  { style: { marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' } },
                  h(
                    'button',
                    { style: { ...button, borderColor: 'var(--dsw-alias-accent, #247bbf)', color: 'var(--dsw-alias-accent, #247bbf)' }, disabled: busy === 'deep', onClick: startDeepAudit },
                    busy === 'deep' ? T('处理中…', 'Working…') : T('在新会话中详细审计', 'Deep audit in a new session'),
                  ),
                  current.verdict === 'risk' && !confirming
                    ? h(
                        'button',
                        { style: { ...button, borderColor: 'var(--dsw-alias-danger, #d33)', color: 'var(--dsw-alias-danger, #d33)' }, disabled: busy === 'disable', onClick: () => setConfirming(true) },
                        T('关闭该插件', 'Disable this plugin'),
                      )
                    : null,
                  current.verdict === 'risk' && confirming
                    ? h(
                        'span',
                        { style: { display: 'inline-flex', gap: 8, alignItems: 'center' } },
                        h('span', { style: { fontSize: 12 } }, T(`确认关闭 ${current.plugin}？`, `Disable ${current.plugin}?`)),
                        h('button', { style: { ...button, borderColor: 'var(--dsw-alias-danger, #d33)', color: 'var(--dsw-alias-danger, #d33)' }, disabled: busy === 'disable', onClick: disablePlugin }, busy === 'disable' ? T('处理中…', 'Working…') : T('确认关闭', 'Confirm')),
                        h('button', { style: button, onClick: () => setConfirming(false) }, T('取消', 'Cancel')),
                      )
                    : null,
                  !trusting && busy !== 'trust'
                    ? h(
                        'button',
                        { style: { ...button, borderColor: 'var(--dsw-alias-success, #2a7)', color: 'var(--dsw-alias-success, #2a7)' }, onClick: () => setTrusting(true) },
                        T('标记为误报并信任', 'Trust as false positive'),
                      )
                    : null,
                  trusting
                    ? h(
                        'span',
                        { style: { display: 'inline-flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
                        h('span', { style: { fontSize: 12 } }, T(`确认信任 ${current.plugin}？（仅当前版本；产物变化会重新审计）`, `Trust ${current.plugin}? (this artifact only; a changed artifact is audited again)`) ),
                        h('button', { style: { ...button, borderColor: 'var(--dsw-alias-success, #2a7)', color: 'var(--dsw-alias-success, #2a7)' }, disabled: busy === 'trust', onClick: trustPlugin }, busy === 'trust' ? T('处理中…', 'Working…') : T('确认信任', 'Confirm')),
                        h('button', { style: button, onClick: () => setTrusting(false) }, T('取消', 'Cancel')),
                      )
                    : null,
                  h('button', { style: button, onClick: () => onDismiss(keys, liveKey) }, T('稍后处理', 'Later')),
                ),
                remaining > 0
                  ? h('div', { style: { marginTop: 6, fontSize: 12, opacity: 0.7 } }, T(`另有 ${remaining} 个插件刚完成审计`, `${remaining} more audit result(s) queued`))
                  : null,
                notice ? h('div', { style: { marginTop: 8, fontSize: 12, opacity: 0.85 } }, notice) : null,
                h('div', { style: { marginTop: 8, fontSize: 11, opacity: 0.55 } }, T('静态规则检测，不代表完全安全。', 'Heuristic scan; not a guarantee.')),
              ),
      );
    }

    function SecurityWatchEntry(props) {
      const [state, setState] = React.useState({ live: [], pending: [] });
      const [open, setOpen] = React.useState(false);
      const [dismissed, setDismissed] = React.useState([]);
      const openedAt = React.useRef(Date.now());

      React.useEffect(() => {
        let alive = true;
        const tick = async () => {
          try {
            const res = await fetch('/api/security-watch/state', { credentials: 'same-origin' });
            if (!res.ok) return;
            const next = await res.json();
            if (alive) setState(next);
          } catch {
            // Host route missing or offline: stay quiet.
          }
        };
        tick();
        const timer = setInterval(() => {
          if (document.visibilityState === 'visible') tick();
        }, POLL_MS);
        return () => {
          alive = false;
          clearInterval(timer);
        };
      }, []);

      const dismiss = (keys, liveKey) => {
        markSeen(keys);
        setOpen(false);
        if (liveKey !== undefined) setDismissed((prev) => (prev.includes(liveKey) ? prev : [...prev, liveKey]));
      };

      const count = (state.pending || []).length;
      // A scan that could not run or finish is not "green": surface it as a
      // warning dot even though it has no pending risk record.
      const skippedAttention = (state.live || []).filter(
        (x) => x.status === 'done' && x.skipped === true && (x.reason === 'unresolved' || x.reason === 'watchdog'),
      ).length;
      const dot = count > 0
        ? 'var(--dsw-alias-danger, #d33)'
        : skippedAttention > 0
          ? 'var(--dsw-alias-warning, #c80)'
          : 'var(--dsw-alias-success, #2a7)';

      return h(
        React.Fragment,
        null,
        h(
          'button',
          {
            className: 'security-watch-entry',
            title: T('安全审计', 'Security watch'),
            style: { ...button, display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12 },
            onClick: () => setOpen((value) => !value),
          },
          h('span', { style: { width: 7, height: 7, borderRadius: 4, background: dot } }),
          T('安全', 'Security'),
          count > 0 ? h('span', { style: { fontSize: 11, opacity: 0.8 } }, String(count)) : null,
          count === 0 && skippedAttention > 0 ? h('span', { style: { fontSize: 11, opacity: 0.8 } }, '!') : null,
        ),
        h(Panel, { state, onDismiss: dismiss, ctx: props.ctx, open, openedAt: openedAt.current, dismissed }),
      );
    }

    return {
      inject: ['remote', 'remote.session', 'slots'],
      apply(ctx) {
        ctx.slots.inject('sidebar.footer.action', () =>
          ctx.slots.register(
            {
              name: 'sidebar.footer.action',
              id: 'security-watch',
              order: 90,
            },
            (props) => h(SecurityWatchEntry, { ...props, ctx }),
          ),
        );
      },
    };
  },
});
