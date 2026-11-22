// Electron 主进程 (云端 Linux runner / 本地 Windows 通用)
// 隐藏窗口 + 远程调试端口, 供 playwright connect_over_cdp 驾驶
// 关键: Chromium 152 构建 (与已验证可过 berryhub 雷池 WAF 的内嵌浏览器同构建)
const { app, BrowserWindow } = require('electron');

app.commandLine.appendSwitch('remote-debugging-port', process.env.ELECTRON_CDP_PORT || '9223');
app.commandLine.appendSwitch('no-sandbox');
// 软件 WebGL (SwiftShader): 无 GPU 的 CI 环境补全 canvas/WebGL 指纹
app.commandLine.appendSwitch('use-gl', 'angle');
app.commandLine.appendSwitch('use-angle', 'swiftshader');
app.commandLine.appendSwitch('enable-unsafe-swiftshader');

// 可选代理 (云端经 WARP socks5 访问 berryhub, 换 IP 信誉)
if (process.env.ELECTRON_PROXY) {
  app.commandLine.appendSwitch('proxy-server', process.env.ELECTRON_PROXY);
}

app.whenReady().then(() => {
  const url = process.argv.find(a => a.startsWith('http')) || 'https://berryhub.org/';
  const win = new BrowserWindow({
    show: false,
    width: 1366,
    height: 900,
    webPreferences: { backgroundThrottling: false },
  });
  win.loadURL(url);
});

app.on('window-all-closed', () => app.quit());
