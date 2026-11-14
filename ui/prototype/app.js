/* SCAU Link desktop UI study. All data and connection transitions are local demos. */
(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const esc = value => String(value).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
  const icon = (name, extra = '') => (window.UI_ICONS[name] || window.UI_ICONS['circle-help']).replace(/<svg\b/, `<svg class="icon ${extra}" aria-hidden="true" focusable="false"`);
  const button = (text, action, style = '', glyph = '') => `<button type="button" class="btn ${style}" data-action="${action}">${glyph ? icon(glyph) : ''}${text}</button>`;
  const tag = (text, style = '', glyph = '') => `<span class="tag ${style}">${glyph ? icon(glyph) : ''}${text}</span>`;
  const pageNames = {home:'连接总览',account:'账号与服务',network:'网络适配器',logs:'运行记录',preferences:'偏好设置',about:'关于',setup:'首次使用'};
  const routes = {home:'02-online.html',account:'03-account.html',network:'04-network.html',preferences:'05-preferences.html',logs:'06-logs.html',about:'07-about.html',setup:'08-onboarding.html'};
  const params = new URLSearchParams(location.search);
  const maskAccount = value => value.length>4 ? value.slice(0,4)+'••••'+value.slice(-2) : (value ? value[0]+'•••'+value.slice(-1) : '尚未填写');
  const state = {
    page: params.get('page') || (pageNames[location.hash.slice(1)]?location.hash.slice(1):null) || document.body.dataset.page || 'home',
    connection: params.get('state') || document.body.dataset.state || 'online',
    username:'20260088',pendingUsername:null,password:'',draftAccount:'20260088',draftPassword:'',
    invalid:false,visiblePassword:false,filter:'all',query:'',tray:document.body.dataset.tray==='true',
    minimized:false,logsTab:'events',adapter:'ethernet',scanCount:0,
    settings:{recovery:true,notifications:true,minimize:true,retain:true,launch:false,autoconnect:false},
    keepDemo:false,
    surface:document.body.dataset.surface || 'full',cameFromMini:false,
    miniView:document.body.dataset.view || 'home',miniDetails:document.body.dataset.details==='true',
    miniVisible:true,miniMenu:false,miniContext:false
  };
  if (params.has('embed')) document.body.classList.add('embedded');
  if (params.has('mini-embed')) document.body.classList.add('mini-embed');
  let connectTimer = null, toastTimer = null;
  const events = [
    {time:'09:41:18',title:'校园网认证成功',detail:'已开始新的在线会话。',category:'认证',level:'info',glyph:'circle-check'},
    {time:'09:41:18',title:'在线维护已就绪',detail:'按服务器设置保持当前连接。',category:'连接',level:'info',glyph:'shield-check'},
    {time:'09:41:19',title:'互联网连接正常',detail:'已完成网络可达性检查。',category:'检查',level:'info',glyph:'network'},
    {time:'09:38:05',title:'认证核心已自动恢复',detail:'异常退出后，已重新启动并完成认证。',category:'恢复',level:'warning',glyph:'refresh-cw'},
    {time:'09:38:03',title:'正在准备重新连接',detail:'已保留本次会话，等待 2 秒后重试。',category:'恢复',level:'warning',glyph:'clock-3'},
    {time:'09:30:00',title:'以太网已连接',detail:'当前使用选定的物理有线网卡。',category:'网卡',level:'info',glyph:'ethernet-port'}
  ];
  const connectionNames = {online:'已连接',offline:'未连接',connecting:'正在认证',recovering:'正在恢复连接',rejected:'认证被拒绝',unplugged:'等待网线'};
  const heading = (title, desc, label = '有线 802.1X', glyph = 'ethernet-port') => `<header class="page-heading"><div><h1>${title}</h1><p>${desc}</p></div>${label ? `<span class="heading-label">${icon(glyph)}${label}</span>` : ''}</header>`;
  const navItem = (page, name, glyph) => `<a class="nav-item ${state.page===page?'active':''}" href="${routes[page]}" data-page="${page}" ${state.page===page?'aria-current="page"':''}>${icon(glyph)}<span>${name}</span></a>`;
  const switchRow = (key,title,desc,glyph) => `<div class="row-setting"><div class="setting-icon">${icon(glyph)}</div><div class="setting-copy"><strong>${title}</strong><p>${desc}</p></div><input type="checkbox" class="switch" data-setting="${key}" aria-label="${title}" ${state.settings[key]?'checked':''}></div>`;

  function renderShell() {
    document.body.classList.toggle('mini-surface',state.surface==='mini');
    if(state.surface==='mini') {
      document.title = 'SCAU Link Mini · 托盘小窗预览';
      document.body.innerHTML=window.renderMiniUI({state,icon,button,esc,maskAccount,connectionNames,switchRow,events});
      return;
    }
    document.title = `${pageNames[state.page] || 'SCAU Link'} · SCAU Link 界面预览`;
    document.body.innerHTML = `<header class="preview-bar"><div class="preview-brand">${icon('sprout')}SCAU Link <small>Windows 桌面界面设计</small><span class="preview-badge">CONCEPT 02</span></div><div class="preview-controls"><a class="preview-link" href="overview.html">${icon('panel-top')}设计总览</a><button class="preview-link" data-action="tray">${icon('monitor')}托盘</button><select class="preview-select" aria-label="切换演示状态" id="scenario-select">${Object.entries(connectionNames).map(([key,value])=>`<option value="${key}" ${state.connection===key?'selected':''}>${value}</option>`).join('')}</select><button class="preview-link" data-action="demo-connect">体验连接流程 ${icon('arrow-right')}</button></div></header>
      <div class="desktop-stage" id="stage"><section class="app-window" aria-label="SCAU Link 应用窗口"><header class="titlebar"><span class="titlebar-brand">${icon('sprout')}SCAU Link</span><div class="window-controls"><button class="window-control" data-action="minimize" aria-label="最小化到通知区域">${icon('minus')}</button><button class="window-control" data-action="maximize" aria-label="切换窗口大小">${icon('square')}</button><button class="window-control close" data-action="close-window" aria-label="关闭窗口">${icon('x')}</button></div></header><div class="app-layout"><aside class="sidebar" aria-label="主导航"><div class="sidebar-heading"><strong>SCAU Link</strong><p>轻量 · 原生 · 专注连接</p></div><p class="nav-label">校园网络</p><nav class="nav-list">${navItem('home','连接总览','network')}${navItem('account','账号与服务','user-round')}${navItem('network','网络适配器','ethernet-port')}${navItem('logs','运行记录','list')}</nav><div class="nav-spacer"></div><nav class="nav-list">${navItem('preferences','偏好设置','settings-2')}${navItem('about','关于','info')}</nav><div class="sidebar-status"><span class="dot"></span>认证核心就绪 <span style="margin-left:auto">0.3.0</span></div></aside><main class="main" id="main"></main></div><footer class="statusbar"><span class="statusbar-left"><span class="dot ${state.connection==='online'?'':state.connection==='recovering'?'warning':'offline'}"></span><span id="footer-status">${connectionNames[state.connection]}</span><span>·</span><span>以太网</span></span><span class="statusbar-right"><span>本次会话凭据仅保留在内存</span><span>Windows 原生认证</span></span></footer></section><section class="minimized-message" hidden>${icon('monitor')}<h2>窗口已收起，连接继续保持</h2><p>从通知区域重新打开，不会中断当前会话。</p>${button('重新打开窗口','restore','primary','panel-top')}</section></div><footer class="stage-footer"><span>SCAU LINK / WINDOWS DESKTOP STUDY</span><span>交互示意 · 使用演示数据，不会操作真实网络</span></footer><div id="tray-root"></div><div id="toast-root" aria-live="polite"></div><dialog class="modal" id="modal" aria-labelledby="modal-title"></dialog>`;
    if(state.cameFromMini) {
      const back=document.createElement('button');back.className='preview-link mini-return-link';back.dataset.action='mini-return';back.innerHTML=icon('arrow-left')+'返回 Mini';$('.preview-controls').prepend(back);
    }
    renderPage();renderTray();
  }

  function renderPage() {
    const renderers={home:homePage,account:accountPage,network:networkPage,logs:logsPage,preferences:preferencesPage,about:aboutPage,setup:setupPage};
    $('#main').innerHTML=(renderers[state.page] || homePage)();
    $('.main').scrollTop=0;
  }

  function hero() {
    const s=state.connection;
    if(s==='online') return `<section class="hero"><div class="hero-top"><div><div class="state-indicator"><span class="dot"></span>校园网络已就绪</div><h2>已连接，安心在线。</h2><p>窗口收起后，校园网连接依然保持。</p><div class="hero-account">${icon('user-round')}${esc(maskAccount(state.username))}<span class="separator">·</span>有线 1x 上网</div></div><div class="hero-mark">${icon('network')}</div></div><div class="hero-actions">${button('断开连接','disconnect','','log-out')}${button('查看连接详情','go-network','text','arrow-up-right')}</div><div class="metrics"><div class="metric"><div class="metric-label">${icon('clock-3')}本次在线</div><div class="metric-value duration">02:36:18</div></div><div class="metric"><div class="metric-label">${icon('ethernet-port')}认证网卡</div><div class="metric-value">以太网 <small>100 Mbps</small></div></div><div class="metric"><div class="metric-label">${icon('shield-check')}自动恢复</div><div class="metric-value">${state.settings.recovery?'已开启':'已暂停'}</div></div></div></section>`;
    const copy={
      offline:{title:'准备好，连接校园网。',hint:'输入你的校园网账号，即可开始连接。',label:'当前未连接',glyph:'plug-zap',style:'disconnected',action:button('连接校园网','connect','primary','arrow-right')},
      connecting:{title:'正在连接校园网…',hint:'正在确认你的身份，请稍等片刻。',label:'认证进行中',glyph:'loader-circle',style:'disconnected',action:button('取消连接','cancel','','x')},
      recovering:{title:'正在恢复你的连接。',hint:'认证核心异常退出，已自动启动恢复。',label:'本次会话已保留',glyph:'refresh-cw',style:'warning',action:button('停止自动重连','cancel','','pause')},
      rejected:{title:'校园网认证被拒绝。',hint:'请检查账号与密码，或按校园网提示处理。',label:'需要你处理',glyph:'circle-alert',style:'rejected',action:button('检查账号与密码','go-account','primary','user-round')+button('查看运行记录','go-logs','text','arrow-up-right')},
      unplugged:{title:'等待网线接入。',hint:'检查网线或校园网接口，接入后将继续连接。',label:'以太网未连接',glyph:'cable',style:'warning',action:button('取消等待','cancel','','x')}
    }[s] || {};
    return `<section class="hero ${copy.style}"><div class="hero-top"><div><div class="state-indicator"><span class="dot ${s==='rejected'?'offline':'warning'}"></span>${copy.label}</div><h2>${copy.title}</h2><p>${copy.hint}</p>${s==='recovering'?'<div class="hero-account">重试 2 / 5 · 当前退避 2 秒</div>':''}${s==='rejected'?'<div class="hero-account">自动重试已停止，避免反复提交凭据。</div>':''}</div><div class="hero-mark ${s==='connecting'?'spin':''}">${icon(copy.glyph || 'network')}</div></div><div class="hero-actions">${copy.action}</div>${s==='connecting'?`<div class="connection-steps"><span class="done">网卡就绪</span>${icon('chevron-right','chevron')}<span class="current">身份认证</span>${icon('chevron-right','chevron')}<span>连接检查</span></div><div class="progress-line"><span></span></div>`:''}</section>`;
  }

  function checks() {
    const s=state.connection;
    const connected=s==='online',physical=s!=='unplugged';
    return `<div class="checks"><div class="check-card ${physical?'':'pending'}"><div class="check-icon">${icon('cable')}</div><div><strong>${physical?'网线已接入':'未检测到网线'}</strong><p>${physical?'物理连接正常':'等待以太网链路'}</p></div></div><div class="check-card ${connected?'':'neutral'}"><div class="check-icon">${icon('shield-check')}</div><div><strong>${connected?'校园网已认证':s==='recovering'||s==='connecting'?'正在重新认证':'校园网待认证'}</strong><p>${connected?'当前会话有效':s==='rejected'?'请检查账号设置':'等待认证结果'}</p></div></div><div class="check-card ${connected?'':'neutral'}"><div class="check-icon">${icon('network')}</div><div><strong>${connected?'互联网可访问':'互联网待检查'}</strong><p>${connected?'最近检查通过':'认证后单独检查'}</p></div></div></div>`;
  }

  function homePage() {
    const s=state.connection;
    let content=heading('连接总览','随时了解你的校园网连接状态。')+hero();
    if(s==='offline') content+=`<div class="section-title"><h2>快速连接</h2><button data-page="account">账号与服务 ${icon('chevron-right')}</button></div><section class="panel"><div class="form-grid"><div class="field ${state.invalid&&!state.username?'error':''}"><label for="quick-username">校园网账号</label><input id="quick-username" name="username" autocomplete="off" spellcheck="false" placeholder="请输入校园网账号" value="${esc(state.username)}">${state.invalid&&!state.username?'<span class="error-text">请输入校园网账号</span>':''}</div><div class="field ${state.invalid&&!state.password?'error':''}"><label for="quick-password">密码</label><div class="input-wrap"><input id="quick-password" name="password" type="${state.visiblePassword?'text':'password'}" autocomplete="off" placeholder="仅用于本次会话" value="${esc(state.password)}"><button type="button" class="input-icon" data-action="toggle-quick-password" aria-label="${state.visiblePassword?'隐藏密码':'显示密码'}">${icon(state.visiblePassword?'eye-off':'eye')}</button></div>${state.invalid&&!state.password?'<span class="error-text">请输入密码，或点击上方体验连接流程</span>':''}</div></div><div class="selected-summary">${icon('ethernet-port')}以太网<span>有线 1x 上网</span></div></section>`;
    if(s==='recovering') content+=`<div class="recovery-progress">${icon('loader-circle','spin')}<div><strong>等待下一次认证</strong><p>使用本次会话重新连接，无需再次输入密码。</p></div>${tag('2 秒后重试','amber')}</div><div class="step-list"><div class="step-row"><span class="step-icon">${icon('check')}</span>检测到认证核心异常<span>09:38:01</span></div><div class="step-row"><span class="step-icon">${icon('check')}</span>已重新启动认证核心<span>09:38:02</span></div><div class="step-row current"><span class="step-icon">${icon('loader-circle','spin')}</span>等待重新认证<span>进行中</span></div></div>`;
    if(s==='rejected') content+=`<div class="notice">${icon('info')}<span>明确的认证拒绝会停止自动重连。修改账号后，请主动发起新的连接。</span></div>`;
    content+=`<div class="section-title"><h2>连接检查</h2>${s==='online'?'<button data-action="check-connection">重新检查 '+icon('refresh-cw')+'</button>':''}</div>${checks()}`;
    if(s==='online')content+=`<div class="section-title"><h2>最近活动</h2><button data-page="logs">全部记录 ${icon('chevron-right')}</button></div><div class="activity"><div class="activity-line">${icon('circle-check')}<strong>校园网认证成功</strong><span>会话已建立</span><time>09:41:18</time></div><div class="activity-line">${icon('shield-check')}<strong>在线维护已就绪</strong><span>按服务器设置保持连接</span><time>09:41:18</time></div></div>`;
    return content;
  }

  function accountPage() {
    return heading('账号与服务','管理你的校园网身份和认证方式。','会话凭据','shield-check')+`<div class="account-summary"><div class="avatar">${icon('user-round')}</div><div><strong>校园网账号</strong><p>当前账号：${esc(maskAccount(state.username))}</p></div>${tag('仅本次会话','green','lock-keyhole')}</div><section class="panel"><div class="panel-head"><div><h2>登录凭据</h2><p>使用学校统一分配的校园网账号。</p></div>${icon('user-round')}</div><div class="form-grid"><div class="field"><label for="account-username">账号</label><input id="account-username" autocomplete="off" spellcheck="false" value="${esc(state.draftAccount)}" placeholder="请输入校园网账号"></div><div class="field"><label for="account-password">密码</label><div class="input-wrap"><input id="account-password" type="password" autocomplete="off" value="${esc(state.draftPassword)}" placeholder="输入或修改密码"><button class="input-icon" type="button" data-action="toggle-account-password" aria-label="显示账号密码">${icon('eye')}</button></div></div></div><div class="form-bottom"><label class="checkbox-label"><input type="checkbox" data-setting="retain" ${state.settings.retain?'checked':''}>在本次会话中保留凭据，用于自动重连</label>${button(state.connection==='online'?'保存设置':'保存并连接',state.connection==='online'?'save-account':'save-account-connect','primary','check')}</div></section><section class="panel"><div class="panel-head"><div><h2>认证服务</h2><p>适用于 SCAU 校园网的有线认证。</p></div></div><div class="service-tile"><span class="radio-circle"></span><div><strong>有线 1x 上网</strong><p>使用所选物理以太网卡完成认证</p></div>${icon('ethernet-port')}</div></section><p class="subtle-note">${icon('shield-check')}关闭应用后清除本次会话凭据，不把密码写入配置或日志。</p>`;
  }

  function networkPage() {
    return heading('网络适配器','固定使用物理有线网卡，让连接更可靠。','3 个适配器','ethernet-port')+`<section class="adapter-card selected"><div class="adapter-icon">${icon('ethernet-port')}</div><div class="adapter-copy"><strong>以太网</strong><p>Realtek Gaming 2.5GbE Family Controller</p></div>${tag('正在使用','green')}${icon('circle-check')}</section><section class="adapter-card disabled"><div class="adapter-icon">${icon('wifi')}</div><div class="adapter-copy"><strong>Wi-Fi</strong><p>无线网卡 · 当前未连接</p></div>${tag('不用于有线认证')}</section><section class="adapter-card disabled"><div class="adapter-icon">${icon('network')}</div><div class="adapter-copy"><strong>虚拟网络适配器</strong><p>VPN / TUN · 不作为校园网认证接口</p></div>${tag('已排除')}</section><div class="section-title"><h2>以太网详情</h2>${button('刷新适配器','refresh-adapters','small','refresh-cw')}</div><section class="panel"><div class="detail-grid"><div class="detail-row"><span>连接状态</span><span>网线已接入</span></div><div class="detail-row"><span>链路速度</span><span>100 Mbps</span></div><div class="detail-row"><span>IPv4 地址</span><span>192.0.2.16</span></div><div class="detail-row"><span>认证服务</span><span>有线 1x 上网</span></div><div class="detail-row"><span>网卡类型</span><span>物理以太网</span></div><div class="detail-row"><span>网卡选择</span><span>固定使用当前网卡</span></div></div></section><p class="subtle-note">${icon('info')}连接只使用选定网卡，不会切换 VPN 路由或修改网卡配置。</p>`;
  }

  function preferencesPage() {
    return heading('偏好设置','让客户端按你的习惯安静运行。','会话设置','sliders-horizontal')+`<div class="settings-group-label">连接与恢复</div><section class="panel">${switchRow('recovery','认证核心异常后自动恢复','在当前会话内重新认证；主动断开后保持离线。','refresh-cw')}${switchRow('notifications','连接状态通知','仅在断开、恢复成功或需要处理时提醒。','bell')}</section><div class="settings-group-label">窗口与通知区域</div><section class="panel">${switchRow('minimize','关闭窗口时收起到通知区域','保持当前连接，可从通知区域重新打开。','monitor')}<div class="row-setting"><div class="setting-icon">${icon('moon')}</div><div class="setting-copy"><strong>应用外观</strong><p>使用与 Windows 协调的浅色界面。</p></div><select class="setting-select" aria-label="应用外观"><option>浅色</option><option>跟随系统</option></select></div></section><div class="settings-group-label">启动方式</div><section class="panel">${switchRow('launch','登录 Windows 后启动应用','启动应用只打开窗口，不会立即发起认证。','power')}${switchRow('autoconnect','打开应用后尝试连接','需要你先提供本次会话的账号与密码。','plug-zap')}</section><p class="subtle-note">${icon('shield-check')}明确的服务器拒绝和手动断开，会优先于所有自动恢复设置。</p>`;
  }

  function logRows() {
    const query=state.query.trim().toLowerCase();
    const rows=events.filter(e=>(state.filter==='all'||e.level==='warning')&&(!query||(e.title+e.detail+e.category).toLowerCase().includes(query)));
    return rows.length?rows.map(e=>`<article class="log-row"><time class="log-time">${e.time}</time><span class="log-icon ${e.level==='warning'?'warning':''}">${icon(e.glyph)}</span><div class="log-content"><strong>${esc(e.title)}</strong><p>${esc(e.detail)}</p></div><span class="log-category">${e.category}</span></article>`).join(''):`<div class="empty-state">没有匹配的记录，试试其他关键词。</div>`;
  }
  function logsPage() {
    return heading('运行记录','从网卡到认证，让每一次连接都有迹可循。','仅保存必要事件','shield-check')+`<div class="log-toolbar"><div class="search-box">${icon('search')}<input id="log-search" aria-label="搜索运行记录" placeholder="搜索事件或关键词…" value="${esc(state.query)}"></div><div class="segmented" aria-label="日志筛选"><button data-filter="all" class="${state.filter==='all'?'active':''}">全部</button><button data-filter="warning" class="${state.filter==='warning'?'active':''}">异常与恢复</button></div></div><section class="panel log-list"><div class="log-day"><span>今天 · 2026 年 11 月 12 日</span><span>本次应用会话</span></div><div id="log-rows">${logRows()}</div></section><div class="log-footer"><span>记录不包含密码、认证摘要或会话密钥</span><div class="log-actions">${button('复制摘要','copy-summary','small','copy')}${button('导出诊断','export','small','download')}</div></div><div class="section-title"><h2>连接检查</h2><button data-action="check-connection">运行检查 ${icon('arrow-right')}</button></div>${checks()}<p class="subtle-note">${icon('lock-keyhole')}诊断导出自动隐藏账号和网络地址，便于排查问题。</p>`;
  }

  function aboutPage() {
    return heading('关于','一个轻量、专注的校园网认证客户端。','', '')+`<section class="about-hero"><div class="app-logo">${icon('sprout')}</div><h2>SCAU Link</h2><p>让校园网连接，简单一点。</p>${tag('认证核心 0.3.0 · Windows x64','outline')}</section><section class="panel"><div class="about-row"><span>客户端</span><span>Windows 原生桌面</span></div><div class="about-row"><span>开源许可</span><span>GPL-3.0</span></div><div class="about-row"><span>网络驱动</span><span>WinPcap / Npcap</span></div><div class="about-row"><span>版本记录</span>${button('查看更新说明','changelog','text','arrow-up-right')}</div><div class="about-row"><span>第三方组件</span>${button('查看开源致谢','licenses','text','arrow-up-right')}</div></section><div class="about-bottom">为 SCAU 有线校园网设计 · 非学校官方客户端<br>界面设计预览 02 · 所有数据均为示意</div>`;
  }

  function setupPage() {
    return heading('欢迎使用','开始前，先确认连接所需的环境。','首次设置','sprout')+`<section class="welcome"><div class="app-logo">${icon('sprout')}</div><h2>校园网，轻松连接。</h2><p>只需准备好网线和校园网账号。</p></section><div class="setup-steps"><span>${icon('circle-check')}检查环境</span><i></i><span>填写账号</span><i></i><span>开始连接</span></div><section class="panel"><div class="setup-item">${icon('monitor')}<div><strong>Windows 环境</strong><p>适用于 Windows 11 · 64 位</p></div>${tag('已就绪','green','check')}</div><div class="setup-item">${icon('ethernet-port')}<div><strong>物理以太网</strong><p>已找到有线网卡，并检测到网线接入。</p></div>${tag('已就绪','green','check')}</div><div class="setup-item">${icon('shield-check')}<div><strong>网络收发组件</strong><p>已检测到 WinPcap / Npcap 驱动。</p></div>${tag('已就绪','green','check')}</div></section><div class="welcome-actions"><span>环境检查不会发起认证或断开网络。</span>${button('继续设置账号','go-account','primary','arrow-right')}</div>`;
  }

  function go(page) {
    if(!pageNames[page]) return;
    if(state.surface==='mini') {state.miniView=page==='setup'?'account':page;state.miniMenu=false;state.miniContext=false;}
    state.page=page;state.invalid=false;
    renderShell();
    try{history.replaceState(null,'',`#${page}`);}catch(_){}
  }
  function setConnection(next) {
    if(connectTimer){clearTimeout(connectTimer);connectTimer=null;}
    state.connection=next;state.invalid=false;state.minimized=false;
    state.miniView='home';state.miniDetails=false;state.miniMenu=false;state.miniContext=false;
    state.page='home';renderShell();
  }
  function connect(demo=false) {
    if(demo){state.username='20260088';state.pendingUsername=null;state.password='demo-only';}
    const nextUsername=state.pendingUsername || state.username;
    if(!nextUsername.trim()||!state.password){state.invalid=true;state.page='home';state.connection='offline';if(state.surface==='mini'){state.miniView='account';state.miniVisible=true;}renderShell();(state.surface==='mini'?$('#account-password'):$('#quick-username'))?.focus();return;}
    state.username=nextUsername;state.pendingUsername=null;
    setConnection('connecting');
    connectTimer=setTimeout(()=>{state.password='';state.draftPassword='';setConnection('online');toast('校园网已连接（演示），当前网络未被操作。');},2300);
  }
  function toast(text) {
    clearTimeout(toastTimer);$('#toast-root').innerHTML=`<div class="toast" role="status">${icon('circle-check')}${esc(text)}</div>`;
    toastTimer=setTimeout(()=>{$('#toast-root').innerHTML='';},3300);
  }
  function renderTray() {
    $('#tray-root').innerHTML=state.tray?`<aside class="tray-popup" aria-label="通知区域菜单"><div class="tray-header">${icon('sprout')}<div><strong>SCAU Link</strong><p>${connectionNames[state.connection]}${state.connection==='online'?' · 02:36:18':''}</p></div></div><button class="tray-item" data-action="restore">${icon('panel-top')}打开主窗口</button><button class="tray-item" data-action="${state.connection==='online'?'disconnect':'demo-connect'}">${icon(state.connection==='online'?'log-out':'plug-zap')}${state.connection==='online'?'断开连接':'连接校园网'}</button><button class="tray-item" data-page="logs">${icon('list')}查看运行记录</button><div class="tray-separator"></div><button class="tray-item" data-action="exit">${icon('power')}退出应用</button></aside><div class="mini-taskbar" aria-label="模拟 Windows 通知区域">${icon('chevron-down')}${icon('sprout')}${icon('ethernet-port')}<span>12:17</span></div>`:'';
  }
  function openModal(title,description,actions,extra='',glyph='info') {
    const modal=$('#modal');
    modal.innerHTML=`<div class="modal-body"><div class="modal-icon">${icon(glyph)}</div><h2 id="modal-title">${title}</h2><p>${description}</p>${extra}</div><footer class="modal-actions">${actions}</footer>`;
    modal.showModal();
  }
  function closeModal(){$('#modal')?.close();}
  function summary() {return {prototype:true,version:'ui-concept-02',authenticationCore:'0.3.0',connection:connectionNames[state.connection],adapter:'physical-ethernet',account:'[已隐藏]',addresses:'[已隐藏]',credentials:'[不导出]',events:events.map(({time,title,category,level})=>({time,title,category,level}))};}

  function miniHide() {
    state.miniVisible=false;state.miniMenu=false;state.miniContext=false;state.miniView='home';state.miniDetails=false;state.invalid=false;
    state.draftPassword='';renderShell();$('.tray-launcher')?.focus();
  }
  function miniShow() {
    state.miniVisible=true;state.miniContext=false;state.miniMenu=false;state.miniView='home';state.miniDetails=false;
    renderShell();$('.mini-disclosure')?.focus();
  }
  function miniFull(page='home') {
    state.surface='full';state.cameFromMini=true;state.tray=false;state.miniMenu=false;state.miniContext=false;state.page=page;
    document.body.classList.remove('mini-embed');renderShell();
  }

  document.addEventListener('input',event=>{
    const t=event.target;
    if(t.id==='quick-username'){state.username=t.value;state.pendingUsername=null;}
    if(t.id==='quick-password')state.password=t.value;
    if(t.id==='account-username')state.draftAccount=t.value;
    if(t.id==='account-password')state.draftPassword=t.value;
    if(t.id==='log-search'){state.query=t.value;$('#log-rows').innerHTML=logRows();}
  });
  document.addEventListener('change',event=>{
    const t=event.target;
    if(t.id==='scenario-select'){state.miniVisible=true;setConnection(t.value);return;}
    if(t.dataset.setting){state.settings[t.dataset.setting]=t.checked;toast('偏好已在本次预览中更新。');}
  });
  document.addEventListener('keydown',event=>{
    if(event.key==='Enter' && ['quick-username','quick-password'].includes(event.target.id)){event.preventDefault();connect();}
    if(state.surface==='mini' && event.key==='Enter' && ['account-username','account-password'].includes(event.target.id)){event.preventDefault();$('.mini-subview [data-action="save-account-connect"], .mini-subview [data-action="save-account"]')?.click();}
    if(state.surface==='mini' && event.key==='Escape' && !$('#modal')?.open) {
      event.preventDefault();
      if(state.miniContext){state.miniContext=false;renderShell();$('.tray-launcher')?.focus();}
      else if(state.miniMenu){state.miniMenu=false;renderShell();$('[data-action="mini-menu"]')?.focus();}
      else if(state.miniView!=='home'){state.draftPassword='';go('home');$('.mini-disclosure')?.focus();}
      else if(state.miniDetails){state.miniDetails=false;renderShell();$('.mini-disclosure')?.focus();}
      else miniHide();
    }
    if(state.surface==='mini' && event.shiftKey && event.key==='F10' && event.target.closest('.tray-launcher')){event.preventDefault();state.miniContext=true;state.miniVisible=false;renderShell();$('.tray-context button')?.focus();}
  });
  document.addEventListener('contextmenu',event=>{
    if(state.surface==='mini' && event.target.closest('.tray-launcher')){event.preventDefault();state.miniVisible=false;state.miniMenu=false;state.miniContext=true;renderShell();$('.tray-context button')?.focus();}
  });
  document.addEventListener('click',async event=>{
    const link=event.target.closest('a[data-page], button[data-page]');
    if(link){event.preventDefault();state.minimized=false;state.tray=false;go(link.dataset.page);return;}
    const filter=event.target.closest('[data-filter]');
    if(filter){state.filter=filter.dataset.filter;renderPage();return;}
    const trigger=event.target.closest('[data-action]');
    if(!trigger){
      if(state.surface==='mini' && event.target.closest('.mini-desktop') && !event.target.closest('.mini-window, .tray-context'))miniHide();
      else if(state.surface==='mini' && state.miniMenu && !event.target.closest('.mini-more')){state.miniMenu=false;renderShell();}
      return;
    }
    const action=trigger.dataset.action;
    if(action.startsWith('go-')){go(action.slice(3));return;}
    switch(action){
      case 'mini-tray':if(state.miniVisible)miniHide();else miniShow();break;
      case 'mini-hide':miniHide();break;
      case 'mini-show':miniShow();break;
      case 'mini-back':state.draftPassword='';go('home');$('.mini-disclosure')?.focus();break;
      case 'mini-menu':state.miniMenu=!state.miniMenu;renderShell();if(state.miniMenu)$('.mini-more button')?.focus();else $('[data-action="mini-menu"]')?.focus();break;
      case 'mini-details':state.miniDetails=!state.miniDetails;renderShell();$('.mini-disclosure')?.focus();break;
      case 'mini-connect':
        state.miniVisible=true;state.miniContext=false;
        if(state.password)connect();else {state.draftAccount=state.pendingUsername || state.username;state.draftPassword='';go('account');$('#account-password')?.focus();}
        break;
      case 'mini-full':miniFull(state.miniView==='home'?'home':state.miniView);break;
      case 'mini-full-network':miniFull('network');break;
      case 'mini-full-logs':miniFull('logs');break;
      case 'mini-return':state.surface='mini';state.minimized=false;miniShow();break;
      case 'connect':connect();break;
      case 'demo-connect':connect(true);break;
      case 'disconnect':case 'cancel':setConnection('offline');state.password='';toast('已主动断开，自动重连已暂停。（演示）');break;
      case 'toggle-quick-password':{state.visiblePassword=!state.visiblePassword;const field=$('#quick-password');field.type=state.visiblePassword?'text':'password';trigger.innerHTML=icon(state.visiblePassword?'eye-off':'eye');trigger.setAttribute('aria-label',state.visiblePassword?'隐藏密码':'显示密码');break;}
      case 'toggle-account-password':{const field=$('#account-password');const visible=field.type==='password';field.type=visible?'text':'password';trigger.innerHTML=icon(visible?'eye-off':'eye');trigger.setAttribute('aria-label',visible?'隐藏账号密码':'显示账号密码');break;}
      case 'save-account':case 'save-account-connect':{
        if(state.surface==='mini' && (!state.draftAccount.trim() || (action==='save-account-connect'&&!state.draftPassword))){state.invalid=true;renderShell();$(state.draftAccount.trim()?'#account-password':'#account-username')?.focus();break;}
        if(!state.draftAccount.trim()){toast('请先填写校园网账号。');$('#account-username').focus();break;}
        if(action==='save-account'&&state.connection==='online')state.pendingUsername=state.draftAccount.trim();
        else {state.username=state.draftAccount.trim();state.pendingUsername=null;}
        state.password=state.draftPassword;state.draftPassword='';$('#account-password').value='';
        if(action==='save-account-connect')connect();else {if(state.surface==='mini')go('home');toast('账号已用于本次预览，下次连接生效，密码不会写入磁盘。');}break;
      }
      case 'refresh-adapters':state.scanCount++;toast('已刷新：发现 1 个可用于认证的物理以太网卡。（演示）');break;
      case 'check-connection':toast(state.connection==='online'?'网线、校园网认证和互联网检查均通过。（演示）':'网线检查通过；校园网认证尚未完成。（演示）');break;
      case 'maximize':document.body.classList.toggle('fullscreen');break;
      case 'tray':state.surface='mini';state.cameFromMini=true;miniShow();break;
      case 'minimize':state.surface='mini';state.cameFromMini=true;miniHide();break;
      case 'restore':state.minimized=false;$('.app-window').hidden=false;$('.minimized-message').hidden=true;state.tray=false;renderTray();break;
      case 'close-window':if(state.settings.minimize){state.surface='mini';state.cameFromMini=true;miniHide();}else openModal('退出 SCAU Link？','退出应用会结束当前会话，并断开校园网连接。',button('取消','modal-cancel')+button('退出并断开','confirm-exit','danger'),'','log-out');break;
      case 'exit':openModal('退出 SCAU Link？','退出将结束当前会话。若想保持在线，可以收起窗口。',button('取消','modal-cancel')+button('退出并断开','confirm-exit','danger'),'','log-out');break;
      case 'confirm-exit':closeModal();state.tray=false;state.password='';state.draftPassword='';setConnection('offline');toast('演示会话已结束，真实网络连接保持不变。');break;
      case 'modal-cancel':closeModal();break;
      case 'changelog':openModal('本版更新','认证核心 0.3.0',button('知道了','modal-cancel','primary'),'<ul class="modal-list"><li>完成 SAM 加密维护通道</li><li>认证核心崩溃后自动重新登录</li><li>明确拒绝与手动断开停止重试</li><li>当前界面为独立 HTML 设计预览</li></ul>','file-text');break;
      case 'licenses':openModal('开源与致谢','SCAU Link 使用以下开源组件。',button('关闭','modal-cancel','primary'),'<ul class="modal-list"><li>认证核心与 MiniEAP 哈希 · GPL-3.0</li><li>Lucide 图标 0.468.0 · ISC</li><li>WinPcap / Npcap · 独立运行依赖</li></ul>','sprout');break;
      case 'copy-summary':{
        const text=JSON.stringify(summary(),null,2);
        try{await navigator.clipboard.writeText(text);toast('脱敏演示摘要已复制。');}catch(_){openModal('诊断摘要','当前页面无法访问剪贴板，可导出诊断文件。',button('关闭','modal-cancel')+button('导出诊断','export','primary'),'','file-text');}
        break;
      }
      case 'export':{
        closeModal();const file=new Blob([JSON.stringify(summary(),null,2)],{type:'application/json;charset=utf-8'});const url=URL.createObjectURL(file);const anchor=document.createElement('a');anchor.href=url;anchor.download='scau-link-demo-diagnostics.json';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('已导出脱敏演示诊断，不含输入的账号或密码。');break;
      }
    }
  });
  window.addEventListener('beforeunload',()=>{state.password='';state.draftPassword='';});
  renderShell();
})();
