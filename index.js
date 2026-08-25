// ============================================================
// index.js - تست سرعت کانفیگ‌های V2Ray (نسخه نهایی با تشخیص پرچم)
// ============================================================

const axios = require("axios");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { v4: uuidv4 } = require("uuid");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

// -------- تنظیمات --------
const CONFIG = {
  configsFile: "./configs.txt",
  speedThresholdMbps: 10.0,
  timeoutMs: 30000,
  concurrency: 1,
  outputFile: "./result.txt",
  xrayPath: process.env.XRAY_PATH || "./xray/xray.exe",
  testFileUrls: [
    "http://ipv4.download.thinkbroadband.com/10MB.zip",
    "http://speedtest.tele2.net/10MB.zip",
    "http://speedtest.tele2.net/5MB.zip",
    "https://proof.ovh.net/files/10Mb.dat",
  ],
};

// ============================================================
//  بخش ۱: خواندن کانفیگ‌ها از فایل
// ============================================================

function getConfigsFromFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`❌ فایل ${filePath} پیدا نشد!`);
    process.exit(1);
  }
  const content = fs.readFileSync(filePath, "utf8");
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter(
      (line) => line.length > 0 && /^(vmess|vless|trojan|ss):\/\//i.test(line),
    );
}

// ============================================================
//  بخش ۲: استخراج پرچم از نام (نسخه‌ی اثبات‌شده از پروژه‌ی قبلی)
// ============================================================

function extractFlagFromName(name) {
  if (!name) return "";
  let decoded = name;
  try {
    decoded = decodeURIComponent(name);
  } catch (e) {
    // اگر دیکد نشد، همان نام را نگه دار
  }
  const flagRegex = /[\u{1F1E6}-\u{1F1FF}]{2}/u;
  const match = decoded.match(flagRegex);
  if (match) return match[0];
  return "";
}

// ============================================================
//  بخش ۳: پارس کردن لینک‌ها (با پشتیبانی کامل از ss)
// ============================================================

function parseLinkToXrayConfig(link, socksPort) {
  // -------- vmess:// --------
  if (link.startsWith("vmess://")) {
    const base64 = link.substring(8);
    const jsonStr = Buffer.from(base64, "base64").toString("utf-8");
    const parsed = JSON.parse(jsonStr);
    return {
      inbounds: [
        {
          port: socksPort,
          protocol: "socks",
          settings: { auth: "noauth", udp: true },
        },
      ],
      outbounds: [
        {
          protocol: "vmess",
          settings: {
            vnext: [
              {
                address: parsed.add,
                port: parseInt(parsed.port),
                users: [
                  {
                    id: parsed.id,
                    encryption: parsed.scy || "auto",
                    flow: parsed.fp || "",
                    level: 0,
                  },
                ],
              },
            ],
          },
          streamSettings: {
            network: parsed.net || "tcp",
            security: parsed.tls || "",
            tlsSettings: parsed.tls ? { serverName: parsed.sni || "" } : null,
            realitySettings: null,
          },
        },
      ],
    };
  }

  // -------- vless:// (با REALITY) --------
  if (link.startsWith("vless://")) {
    const url = new URL(link);
    const host = url.hostname;
    const port = url.port || 443;
    const id = url.username;
    const params = new URLSearchParams(url.search);
    const encryption = params.get("encryption") || "none";
    const flow = params.get("flow") || "";
    const security = params.get("security") || "";
    const sni = params.get("sni") || host;
    const network = params.get("type") || "tcp";
    const pbk = params.get("pbk") || "";
    const sid = params.get("sid") || "";
    const fp = params.get("fp") || "";

    let streamSettings = { network, security };
    if (security === "reality") {
      streamSettings.realitySettings = {
        serverName: sni,
        publicKey: pbk,
        shortId: sid,
        fingerprint: fp || "chrome",
      };
      streamSettings.tlsSettings = null;
    } else if (security) {
      streamSettings.tlsSettings = { serverName: sni };
      streamSettings.realitySettings = null;
    } else {
      streamSettings.tlsSettings = null;
      streamSettings.realitySettings = null;
    }

    return {
      inbounds: [
        {
          port: socksPort,
          protocol: "socks",
          settings: { auth: "noauth", udp: true },
        },
      ],
      outbounds: [
        {
          protocol: "vless",
          settings: {
            vnext: [
              {
                address: host,
                port: parseInt(port),
                users: [{ id, encryption, flow, level: 0 }],
              },
            ],
          },
          streamSettings,
        },
      ],
    };
  }

  // -------- trojan:// --------
  if (link.startsWith("trojan://")) {
    const url = new URL(link);
    const host = url.hostname;
    const port = url.port || 443;
    const password = url.username;
    const params = new URLSearchParams(url.search);
    const sni = params.get("sni") || host;
    const security = params.get("security") || "tls";

    return {
      inbounds: [
        {
          port: socksPort,
          protocol: "socks",
          settings: { auth: "noauth", udp: true },
        },
      ],
      outbounds: [
        {
          protocol: "trojan",
          settings: {
            servers: [
              { address: host, port: parseInt(port), password, level: 0 },
            ],
          },
          streamSettings: {
            network: "tcp",
            security,
            tlsSettings: { serverName: sni },
            realitySettings: null,
          },
        },
      ],
    };
  }

  // -------- ss:// (پشتیبانی کامل از فرمت‌های مختلف) --------
  if (link.startsWith("ss://")) {
    let content = link.substring(5);
    if (content.includes("#")) content = content.split("#")[0];

    let method, password, host, port;

    if (content.includes("@")) {
      const [encoded, hostPort] = content.split("@");
      let decoded;
      try {
        decoded = Buffer.from(encoded, "base64").toString("utf-8");
      } catch (_) {
        decoded = encoded;
      }
      const parts = decoded.split(":");
      if (parts.length >= 2) {
        method = parts[0];
        password = parts.slice(1).join(":");
      } else {
        const plainParts = encoded.split(":");
        if (plainParts.length >= 2) {
          method = plainParts[0];
          password = plainParts.slice(1).join(":");
        } else {
          throw new Error("فرمت ss نامعتبر");
        }
      }
      const hostPortParts = hostPort.split(":");
      host = hostPortParts[0];
      port = hostPortParts[1] || "443";
    } else if (content.includes("?")) {
      const [hostPort, query] = content.split("?");
      const hostPortParts = hostPort.split(":");
      host = hostPortParts[0];
      port = hostPortParts[1] || "443";
      const params = new URLSearchParams(query);
      method = params.get("method");
      password = params.get("password");
      if (!method || !password) throw new Error("فرمت ss نامعتبر");
    } else {
      let decoded;
      try {
        decoded = Buffer.from(content, "base64").toString("utf-8");
      } catch (_) {
        decoded = content;
      }
      if (decoded.includes("@")) {
        const [methodPass, hostPort] = decoded.split("@");
        const parts = methodPass.split(":");
        if (parts.length >= 2) {
          method = parts[0];
          password = parts.slice(1).join(":");
        } else {
          throw new Error("فرمت ss نامعتبر");
        }
        const hostPortParts = hostPort.split(":");
        host = hostPortParts[0];
        port = hostPortParts[1] || "443";
      } else {
        throw new Error("فرمت ss نامعتبر");
      }
    }

    if (!method || !password || !host || !port) {
      throw new Error("فرمت ss نامعتبر");
    }

    return {
      inbounds: [
        {
          port: socksPort,
          protocol: "socks",
          settings: { auth: "noauth", udp: true },
        },
      ],
      outbounds: [
        {
          protocol: "shadowsocks",
          settings: {
            servers: [
              {
                address: host,
                port: parseInt(port),
                method,
                password,
                level: 0,
              },
            ],
          },
        },
      ],
    };
  }

  throw new Error("پروتکل پشتیبانی نشده");
}

// ============================================================
//  بخش ۴: مدیریت پورت‌های تصادفی (بدون تداخل)
// ============================================================

const usedPorts = new Set();

function getRandomPort() {
  let port;
  let attempts = 0;
  do {
    port = Math.floor(Math.random() * (65000 - 10000 + 1)) + 10000;
    attempts++;
    if (attempts > 100) break;
  } while (usedPorts.has(port));
  usedPorts.add(port);
  return port;
}

// ============================================================
//  بخش ۵: تست سرعت با چندین لینک تستی (بدون فایل موقت)
// ============================================================

async function testSpeed(link, xrayPath, timeoutMs, testUrls) {
  return new Promise((resolve) => {
    const testId = uuidv4().slice(0, 8);
    const socksPort = getRandomPort();

    let downloadSpeed = 0;
    let error = null;
    let isResolved = false;

    let xrayConfig;
    try {
      xrayConfig = parseLinkToXrayConfig(link, socksPort);
    } catch (err) {
      console.log(`❌ Parse error: ${err.message}`);
      usedPorts.delete(socksPort);
      resolve({ link, speed: 0, error: `Parse error: ${err.message}` });
      return;
    }

    const xrayProc = spawn(xrayPath, ["run", "-config", "stdin:"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    xrayProc.stdin.write(JSON.stringify(xrayConfig, null, 2));
    xrayProc.stdin.end();

    let xrayLog = "";
    xrayProc.stdout.on("data", (data) => {
      const str = data.toString();
      xrayLog += str;
      console.log(`[Xray ${testId}] stdout:`, str.trim());
    });
    xrayProc.stderr.on("data", (data) => {
      const str = data.toString();
      xrayLog += str;
      console.log(`[Xray ${testId}] stderr:`, str.trim());
    });
    xrayProc.on("error", (err) => {
      console.log(`[Xray ${testId}] process error:`, err.message);
      error = err.message;
    });

    const timeoutHandle = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        xrayProc.kill();
        usedPorts.delete(socksPort);
        console.log(`⏱️ Timeout for ${link.substring(0, 50)}...`);
        resolve({ link, speed: 0, error: "Timeout", log: xrayLog });
      }
    }, timeoutMs + 5000);

    setTimeout(async () => {
      if (isResolved) return;

      try {
        const proxyAgent = new SocksProxyAgent(
          `socks5://127.0.0.1:${socksPort}`,
        );
        let success = false;

        for (const testUrl of testUrls) {
          if (success) break;
          try {
            console.log(
              `🌐 شروع دانلود از ${testUrl} برای ${link.substring(0, 30)}... (پورت: ${socksPort})`,
            );
            const startTime = Date.now();
            const response = await axios({
              method: "get",
              url: testUrl,
              httpAgent: proxyAgent,
              httpsAgent: proxyAgent,
              timeout: timeoutMs,
              responseType: "stream",
            });

            const totalBytes =
              parseInt(response.headers["content-length"]) || 10 * 1024 * 1024;
            let downloaded = 0;

            response.data.on("data", (chunk) => {
              downloaded += chunk.length;
            });

            await new Promise((resolveStream) => {
              response.data.on("end", () => {
                const elapsed = (Date.now() - startTime) / 1000;
                downloadSpeed =
                  elapsed > 0 ? (downloaded * 8) / (elapsed * 1024 * 1024) : 0;
                success = true;
                resolveStream();
              });
              response.data.on("error", (err) => {
                error = err.message;
                resolveStream();
              });
            });
            if (success) break;
          } catch (err) {
            error = err.message;
            console.log(
              `⚠️ لینک تستی ${testUrl} پاسخ نداد، تلاش با لینک بعدی...`,
            );
          }
        }

        if (!success && downloadSpeed === 0) {
          error = error || "همه لینک‌های تستی شکست خوردند";
        }
      } catch (err) {
        error = err.message;
        console.log(`❌ Download error: ${err.message}`);
      } finally {
        clearTimeout(timeoutHandle);
        if (!isResolved) {
          isResolved = true;
          xrayProc.kill();
          usedPorts.delete(socksPort);
          resolve({ link, speed: downloadSpeed, error, log: xrayLog });
        }
      }
    }, 3000);
  });
}

// ============================================================
//  بخش ۶: تابع نوشتن نتیجه به فایل (با حفظ پرچم)
// ============================================================

function appendResult(link, speed) {
  const hashIndex = link.indexOf("#");
  let flag = "";
  if (hashIndex !== -1) {
    const name = link.substring(hashIndex + 1).trim();
    flag = extractFlagFromName(name);
  }
  const cleanLink = link.split("#")[0];
  const speedNum = speed.toFixed(2);

  // اگر پرچم پیدا شد، آن را با یک فاصله قبل از  قرار بده
  const finalName = flag ? `${flag} O` : "O";
  const line = `${cleanLink}#${finalName} (${speedNum})\n`;
  fs.appendFileSync(CONFIG.outputFile, line, "utf8");
}

// ============================================================
//  بخش ۷: تابع اصلی (نوشتن آنی در فایل)
// ============================================================

async function main() {
  console.log("🔄 خواندن لیست کانفیگ‌ها از configs.txt...");
  const allLinks = getConfigsFromFile(CONFIG.configsFile);
  console.log(`✅ تعداد کل کانفیگ‌ها: ${allLinks.length}`);

  if (allLinks.length === 0) {
    console.log("⚠️ هیچ کانفیگی پیدا نشد.");
    process.exit(0);
  }

  fs.writeFileSync(CONFIG.outputFile, "", "utf8");

  let acceptedCount = 0;
  const threshold = CONFIG.speedThresholdMbps;

  for (let i = 0; i < allLinks.length; i += CONFIG.concurrency) {
    const batch = allLinks.slice(i, i + CONFIG.concurrency);
    console.log(
      `\n📦 Batch ${Math.floor(i / CONFIG.concurrency) + 1}: تست ${batch.length} کانفیگ...`,
    );

    const batchPromises = batch.map((link) =>
      testSpeed(link, CONFIG.xrayPath, CONFIG.timeoutMs, CONFIG.testFileUrls),
    );
    const batchResults = await Promise.allSettled(batchPromises);

    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        const data = result.value;
        if (data.speed >= threshold) {
          appendResult(data.link, data.speed);
          acceptedCount++;
          console.log(
            `✅ قبول (${acceptedCount}): ${data.speed.toFixed(2)} Mbps`,
          );
        } else {
          console.log(
            `❌ رد: ${data.speed.toFixed(2)} Mbps (خطا: ${data.error || "ندارد"})`,
          );
        }
      } else {
        console.log(`❌ خطای غیرمنتظره: ${result.reason}`);
      }
    }
    console.log(
      `⏳ پیشرفت: ${Math.min(i + CONFIG.concurrency, allLinks.length)} از ${allLinks.length}`,
    );
  }

  console.log(
    `\n✅ فرآیند کامل شد. تعداد کل کانفیگ‌های قابل قبول: ${acceptedCount}`,
  );
  console.log(`📄 نتایج در فایل ${CONFIG.outputFile} ذخیره شد.`);
}

// اجرا
if (require.main === module) {
  main().catch((err) => {
    console.error("❌ خطای کلی:", err);
    process.exit(1);
  });
}
