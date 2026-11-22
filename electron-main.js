// Electron 主进程 (云端 Linux runner / 本地 Windows 通用)
// 隐藏窗口 + 远程调试端口, 供 playwright connect_over_cdp 驾驶
// 关键: Chromium 152 构建 (与已验证可过 berryhub 雷池 WAF 的内嵌浏览器同构建)
const { app, BrowserWindow } = require('electron');

app.commandLine.appendSwitch('remote-debugging-port', process.env.ELECTRON_CDP_PORT || '9223');
app.commandLine.appendSwitch('no-sandbox');
app.disableHardwareAcceleration();

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
