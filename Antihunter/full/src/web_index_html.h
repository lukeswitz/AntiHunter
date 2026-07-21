#pragma once
#include <pgmspace.h>

static const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html data-theme="light">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>AntiHunter</title>
    <style>
      :root{--t:0.2s;--blur:12px}
      [data-theme="light"]{--bg:linear-gradient(135deg,#edf1f6 0%,#e2e8ef 100%);--surf:rgba(255,255,255,0.9);--surf-hover:rgba(255,255,255,0.95);--bord:rgba(0,0,0,0.08);--bord-focus:rgba(72,136,204,0.35);--txt:#1a2030;--mut:#6878a0;--acc:#4080c8;--acch:#3068a8;--accbg:rgba(64,128,200,0.07);--succ:#4080c8;--warn:#a07830;--dang:#b0473a;--shad:0 8px 32px rgba(0,0,0,0.06);--shad-hover:0 12px 48px rgba(0,0,0,0.1);--glow:0 0 20px rgba(64,128,200,0.12);--backdrop:blur(12px) saturate(180%);--c-ble:#7882a0;--c-ble-bg:rgba(120,130,160,0.1);--c-wifi:#4080c8;--c-wifi-bg:rgba(64,128,200,0.08);--c-rand:#6878a0;--c-known:#4080c8;--c-away:#a07830;--c-away-bg:rgba(160,120,48,0.07);--c-ap:#4080c8;--c-alert:#a07830;--c-alert-bg:rgba(160,120,48,0.05);--c-ok:#4080c8;--c-err:#a05848;--c-err-bg:rgba(160,88,72,0.05)}
      [data-theme="dark"]{--bg:linear-gradient(135deg,#0a0e16 0%,#0e1420 100%);--surf:#131a28;--surf-hover:#1a2333;--bord:#2a3550;--bord-focus:rgba(76,141,255,0.5);--txt:#eaf0fa;--mut:#8a97ad;--acc:#4c8dff;--acch:#6ba5ff;--accbg:rgba(76,141,255,0.1);--succ:#60a0e0;--warn:#c09040;--dang:#d0685a;--shad:0 8px 28px rgba(0,0,0,0.55),0 0 0 1px rgba(76,141,255,0.14),inset 0 1px 0 rgba(255,255,255,0.05);--shad-hover:0 16px 48px rgba(0,0,0,0.7),0 0 0 1px rgba(76,141,255,0.35),inset 0 1px 0 rgba(255,255,255,0.08);--glow:0 0 24px rgba(76,141,255,0.18),0 0 48px rgba(76,141,255,0.06);--backdrop:blur(16px) saturate(180%);--c-ble:#7882a0;--c-ble-bg:rgba(120,130,160,0.12);--c-wifi:#60a0e0;--c-wifi-bg:rgba(96,160,224,0.1);--c-rand:#6878a0;--c-known:#60a0e0;--c-away:#c09040;--c-away-bg:rgba(192,144,64,0.08);--c-ap:#60a0e0;--c-alert:#c09040;--c-alert-bg:rgba(192,144,64,0.06);--c-ok:#60a0e0;--c-err:#b86050;--c-err-bg:rgba(184,96,80,0.06)}
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:var(--bg);background-attachment:scroll;color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.6;transition:background var(--t),color var(--t);min-height:100vh}
      .header{padding:11px 16px;border-bottom:1px solid var(--bord);background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);display:flex;flex-direction:column;gap:11px;box-shadow:var(--shad);position:sticky;top:0;z-index:100}
      .header h1{flex-shrink:0;margin:0;font-size:18px;white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
      .header-bar{display:flex;align-items:center;gap:12px}
      .header-right{display:flex;align-items:center;gap:8px;margin-left:auto;flex-shrink:1;min-width:0;flex-wrap:wrap;justify-content:flex-end;row-gap:8px}
      .page-tabs{flex:0 0 auto;min-width:0;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}
      .page-tabs::-webkit-scrollbar{display:none}
      .header-right .theme-toggle{margin-left:0}
      h1{font-size:20px;font-weight:700;flex-shrink:0;letter-spacing:-0.02em;color:var(--txt)}
      .header h1 b{color:var(--acc);font-weight:700}
      h3{margin:0 0 18px;font-size:16px;font-weight:600;letter-spacing:-0.01em;color:var(--txt)}
      .container{max-width:1400px;margin:0 auto;padding:28px}
      .card{background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);border:1px solid var(--bord);border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:var(--shad);transition:all 0.3s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden}
      .card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent 0%,var(--acc) 50%,transparent 100%);opacity:0;transition:opacity 0.3s}
      .card:hover{box-shadow:var(--shad-hover);border-color:var(--bord-focus);transform:translateY(-2px)}
      .card:hover::before{opacity:0.6}
      label{display:block;margin:10px 0 8px;color:var(--mut);font-size:13px;font-weight:600;letter-spacing:0.01em;text-transform:uppercase}
      input,select,textarea{width:100%;background:var(--surf);border:2px solid var(--bord);border-radius:8px;color:var(--txt);padding:12px 16px;font:inherit;font-size:14px;transition:border-color 0.2s,box-shadow 0.2s;box-shadow:inset 0 1px 3px rgba(0,0,0,0.05)}
      input:hover,select:hover,textarea:hover{border-color:var(--bord-focus)}
      input:focus,select:focus,textarea:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 4px var(--accbg),var(--glow);transform:translateY(-1px)}
      input::placeholder{color:var(--mut);opacity:0.6}
      select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2394a3b8' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}
      [data-theme="dark"] select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234a90e2' d='M10.293 3.293L6 7.586 1.707 3.293A1 1 0 00.293 4.707l5 5a1 1 0 001.414 0l5-5a1 1 0 10-1.414-1.414z'/%3E%3C/svg%3E")}
      textarea{min-height:80px;resize:vertical;line-height:1.5}
      input[type="checkbox"]{width:20px;height:20px;cursor:pointer;position:relative;appearance:none;-webkit-appearance:none;background:var(--bg);border:2px solid var(--acc);border-radius:4px;transition:all 0.2s;flex-shrink:0}
      input[type="checkbox"]:checked{background:var(--acc);border-color:var(--acc);box-shadow:var(--glow)}
      input[type="checkbox"]:checked::after{content:'✓';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#fff;font-size:14px;font-weight:bold}
      input[type="number"]{-moz-appearance:textfield}
      input[type="number"]::-webkit-outer-spin-button,input[type="number"]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
      .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 20px;border-radius:8px;border:2px solid var(--bord);background:var(--surf);color:var(--txt);text-decoration:none;cursor:pointer;font-size:14px;font-weight:600;transition:all 0.2s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden;white-space:nowrap}
      .btn::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;border-radius:50%;background:rgba(255,255,255,0.1);transform:translate(-50%,-50%);transition:width 0.4s,height 0.4s}
      .btn:hover::before{width:300px;height:300px}
      .btn:hover{transform:translateY(-2px);box-shadow:var(--shad-hover);border-color:var(--bord-focus)}
      .btn:active{transform:translateY(0)}
      .btn.primary{background:linear-gradient(135deg,var(--acc) 0%,var(--acch) 100%);border-color:var(--acc);color:#fff;box-shadow:var(--glow)}
      .btn.primary:hover{box-shadow:var(--glow),var(--shad-hover);filter:brightness(1.1)}
      .btn.alt{color:var(--acc);border-color:var(--acc);background:transparent}
      .btn.danger{background:transparent;border-color:var(--dang);color:var(--dang);box-shadow:none}
      .btn.danger:hover{background:var(--dang);color:#fff;box-shadow:none}
      .theme-toggle{width:48px;height:28px;background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:2px solid var(--acc);border-radius:14px;cursor:pointer;position:relative;transition:all 0.3s;margin-left:auto;display:flex;align-items:center;justify-content:center;overflow:hidden;box-shadow:var(--glow)}
      .theme-toggle:hover{transform:scale(1.05);box-shadow:var(--glow),var(--shad)}
      .theme-toggle svg{width:18px;height:18px;position:absolute;transition:opacity 0.3s,transform 0.3s;stroke:var(--acc);fill:var(--acc)}
      .theme-toggle .sun{opacity:1;transform:rotate(0deg) scale(1)}
      .theme-toggle .moon{opacity:0;transform:rotate(90deg) scale(0);stroke:none}
      [data-theme="dark"] .theme-toggle .sun{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="dark"] .theme-toggle .moon{opacity:1;transform:rotate(0deg) scale(1)}
      pre{background:rgba(0,0,0,0.3);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid var(--bord);border-radius:8px;padding:16px;font-size:12px;overflow-x:auto;font-family:monospace;line-height:1.6}
      hr{border:0;border-top:1px solid var(--bord);margin:20px 0}
      .banner{color:var(--dang);border:2px solid var(--dang);padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:600;background:var(--c-err-bg);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      .chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
      .chip-row .chip{padding:6px 12px;border:1px solid var(--bord);border-radius:999px;background:var(--surf);color:var(--mut);font-size:11px;font-weight:600;cursor:pointer;transition:all .15s;user-select:none}
      .chip-row .chip:hover{border-color:var(--acc);color:var(--txt)}
      .chip-row .chip.active{background:var(--acc);color:#fff;border-color:var(--acc);box-shadow:0 0 10px var(--accbg)}
      .field-row{margin-bottom:14px}
      .field-row .field-name{font-size:11px;font-weight:700;display:block;margin-bottom:2px;color:var(--txt);text-transform:uppercase;letter-spacing:.04em}
      .field-row .field-hint{font-size:10px;color:var(--mut);display:block;margin-bottom:6px}
      .psk-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--bord);font-size:11px;font-weight:700;letter-spacing:.03em}
      .psk-badge.set{color:var(--c-ok);border-color:var(--c-ok);background:var(--accbg)}
      .psk-badge.unset{color:var(--warn);border-color:var(--warn);background:var(--c-away-bg)}
      .psk-badge.tamper{color:var(--dang);border-color:var(--dang);background:var(--c-err-bg);animation:scanPulse 1.2s ease-in-out infinite}
      .subcard{padding:12px 14px;background:rgba(0,0,0,0.15);border:1px solid var(--bord);border-radius:10px;margin-bottom:12px;transition:border-color .15s}
      .subcard:hover{border-color:var(--bord-focus)}
      .subcard-head{display:flex;align-items:flex-start;gap:10px;margin-bottom:10px}
      .subcard-num{width:24px;height:24px;border-radius:50%;background:var(--accbg);border:1px solid var(--acc);color:var(--acc);font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
      .subcard-title{font-size:13px;font-weight:700;color:var(--txt);letter-spacing:.02em;line-height:1.2}
      .subcard-sub{font-size:10px;color:var(--mut);margin-top:2px;line-height:1.4}
      #toast{position:fixed;right:24px;bottom:24px;display:flex;flex-direction:column;gap:12px;z-index:9999}
      .toast{background:var(--surf);backdrop-filter:var(--backdrop);-webkit-backdrop-filter:var(--backdrop);border:2px solid var(--bord);padding:14px 18px;border-radius:8px;box-shadow:var(--shad-hover);opacity:0;transform:translateY(12px);transition:opacity 0.3s,transform 0.3s;font-size:14px;min-width:280px}
      .toast.show{opacity:1;transform:none}
      .toast.success{border-color:var(--succ);box-shadow:0 0 24px rgba(96,160,224,0.2)}
      .toast.error{border-color:var(--dang);box-shadow:0 0 24px rgba(184,96,80,0.2)}
      .toast.warning{border-color:var(--warn);box-shadow:0 0 24px rgba(192,144,64,0.2)}
      .status-bar{display:flex;gap:6px;align-items:center;flex-shrink:1;flex-wrap:wrap;justify-content:flex-end}
      .status-item{background:var(--surf);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid var(--bord);padding:4px 10px;border-radius:999px;font-size:10px;font-weight:600;color:var(--mut);transition:border-color .2s,color .2s,background .2s;text-transform:uppercase;letter-spacing:0.04em;display:inline-flex;align-items:center;gap:6px;line-height:1.4;white-space:nowrap;font-variant-numeric:tabular-nums;flex-shrink:0}
      .status-item::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--mut);transition:background .2s,box-shadow .2s;flex-shrink:0}
      .status-item.idle{border-color:rgba(80,180,120,0.4);color:#50b478}
      .status-item.idle::before{background:#50b478;box-shadow:0 0 6px rgba(80,180,120,0.7)}
      .status-item.active{border-color:var(--acc);background:var(--accbg);color:var(--acc)}
      .status-item.active::before{background:var(--acc);box-shadow:0 0 6px var(--acc);animation:scanPulse 2s ease-in-out infinite}
      #scanStatus{min-width:130px;justify-content:flex-start}
      .statx-ticker{flex:1 1 0;min-width:0;overflow-x:auto;overflow-y:hidden;white-space:nowrap;scrollbar-width:none;-webkit-overflow-scrolling:touch}
      .statx-ticker::-webkit-scrollbar{display:none}
      .statx-track{display:inline-flex;align-items:center;gap:6px;flex-wrap:nowrap}
      @keyframes statxScroll{from{transform:translateX(30%)}to{transform:translateX(-100%)}}
      @media(max-width:760px){.header-bar:has(#scanStatus.active) .theme-toggle{display:none}.header-bar:has(#scanStatus.active) .statx-ticker{overflow:hidden}.header-bar:has(#scanStatus.active) .statx-track{animation:statxScroll 14s linear infinite;will-change:transform}.header-bar:has(#scanStatus.active) .statx-ticker:active .statx-track{animation-play-state:paused}}
      @media(prefers-reduced-motion:reduce){.header-bar:has(#scanStatus.active) .statx-track{animation:none}}
      #gpsStatus{min-width:60px;justify-content:flex-start}
      #gpsStatus .gps-acc{text-transform:none;letter-spacing:0;font-size:11px;font-weight:700;margin-left:5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-variant-numeric:tabular-nums}
      #stopAllBtn{padding:7px 16px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;flex-shrink:0}
      @keyframes scanPulse{0%,100%{box-shadow:var(--glow)}50%{box-shadow:0 0 20px rgba(96,160,224,0.3),0 0 40px rgba(96,160,224,0.1)}}
      .tab-buttons{display:flex;gap:6px;margin-bottom:18px;background:rgba(0,0,0,0.1);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:6px;border-radius:10px;border:1px solid var(--bord)}
      .tab-btn{padding:10px 18px;background:transparent;border:none;border-radius:6px;cursor:pointer;color:var(--mut);font-size:13px;font-weight:600;transition:all 0.2s;flex:1;text-align:center}
      .tab-btn.active{background:var(--surf);color:var(--txt);box-shadow:inset 0 1px 0 rgba(255,255,255,0.06),0 0 0 1px var(--bord),0 3px 8px -3px rgba(0,0,0,0.5)}
      .tab-btn:hover:not(.active){color:var(--acc)}
      .tab-content{display:none}
      .tab-content.active{display:block}
      .stat-item{position:relative;overflow:hidden;background:linear-gradient(180deg,var(--surf-hover),var(--surf));backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid var(--bord);padding:18px;border-radius:10px;box-shadow:inset 0 1px 0 rgba(255,255,255,0.05),0 6px 18px -12px rgba(0,0,0,0.6);transition:all 0.2s}
      .stat-item:hover{border-color:var(--bord-focus);transform:translateY(-2px);box-shadow:inset 0 1px 0 rgba(255,255,255,0.08),var(--glow)}
      .stat-label{color:var(--mut);font-size:11px;text-transform:uppercase;margin-bottom:8px;font-weight:700;letter-spacing:0.05em;display:flex;align-items:center;gap:7px}
      .stat-label svg{width:14px;height:14px;stroke:currentColor;color:var(--mut);opacity:0.7;flex-shrink:0}
      .stat-value small{font-size:16px;color:var(--mut);font-weight:500;margin-left:1px}
      .stat-item::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(180deg,var(--bord-focus),transparent 55%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;opacity:0.55;pointer-events:none}
      .card-sub{color:var(--mut);font-size:13px;margin:-12px 0 18px;line-height:1.4}
      .brand-shield{width:auto;height:18px;flex-shrink:0;filter:drop-shadow(0 0 3px var(--acc))}
      .brand-shield path{fill:#fff;stroke:var(--acc);stroke-width:1.4;stroke-linejoin:round;stroke-linecap:round}
      [data-theme="dark"] .brand-shield{filter:drop-shadow(0 0 3px rgba(255,255,255,0.55))}
      [data-theme="dark"] .brand-shield path{fill:var(--acc);stroke:#fff;stroke-width:1.2}
      .stat-value{color:var(--txt);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums;font-size:26px;font-weight:700;letter-spacing:-0.02em}
      .stat-spark{position:absolute;right:12px;bottom:12px;width:60px;height:22px;opacity:0.9;pointer-events:none}
      .stat{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;gap:6px;padding:14px 10px;border:1px solid var(--bord);border-radius:10px;background:var(--accbg);}
      .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
      .card-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none;margin-bottom:18px;padding:4px 0}
      .card-header:hover h3{color:var(--acc)}
      .card-header h3{margin:0;transition:color 0.2s}
      .footer{text-align:center;font-size:11px;color:var(--mut);padding:18px 0 28px;letter-spacing:.4px;opacity:.75}
      .footer #footerNodeId{color:var(--acc);font-weight:600}
      .collapse-icon{transition:transform 0.3s cubic-bezier(0.4,0,0.2,1);font-size:14px;color:var(--mut)}
      .collapse-icon.open{transform:rotate(90deg)}
      .card-body{overflow:hidden;transition:max-height 0.4s cubic-bezier(0.4,0,0.2,1)}
      .card-body.collapsed{max-height:0!important;margin:0;padding:0}
      details>summary{list-style:none;cursor:pointer;font-weight:600;color:var(--acc);margin-bottom:12px;font-size:13px;padding:10px 0;transition:all 0.2s;border-radius:6px}
      details>summary:hover{color:var(--acch)}
      details>summary::-webkit-details-marker{display:none}
      @media(min-width:900px){.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:24px}.grid-node-diag{display:grid;grid-template-columns:minmax(300px,auto) 1fr;gap:24px}.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
      @media(max-width:899px){.grid-2,.grid-node-diag{display:flex;flex-direction:column;gap:20px}.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.container{padding:20px}.card{padding:18px}h1{font-size:18px}}
      @media(max-width:600px){.header{padding:12px 16px;gap:10px}.header h1{font-size:16px}.page-tabs{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;justify-content:flex-start}.page-tabs::-webkit-scrollbar{display:none}.page-tab-btn{padding:7px 12px;font-size:12px}#scanStatus{min-width:0}.status-item{font-size:9px;padding:3px 8px}.status-item::before{width:5px;height:5px}.theme-toggle{flex-shrink:0}.stat-grid,.diag-grid{grid-template-columns:1fr}input,select,textarea{font-size:16px;padding:10px 14px}.btn{padding:10px 16px;font-size:13px}.container{padding:12px}.card{padding:14px}.tab-btn{padding:8px 12px;font-size:12px}#toast{right:12px;bottom:12px;left:12px}.toast{min-width:0;font-size:13px}}
      @media(max-width:820px){.page-tabs{width:100%;justify-content:flex-start}}
      .diag-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
      [data-theme="cyber"]{--bg:#000;--surf:rgba(0,20,0,0.8);--surf-hover:rgba(0,30,0,0.9);--bord:#00cc66;--bord-focus:#00ff88;--txt:#00dd77;--mut:#008855;--acc:#00cc66;--acch:#00ff88;--accbg:rgba(0,204,102,0.1);--succ:#00cc66;--warn:#ffcc00;--dang:#e0604a;--shad:0 0 20px rgba(0,204,102,0.3);--shad-hover:0 0 30px rgba(0,204,102,0.5);--glow:0 0 20px rgba(0,204,102,0.4);--backdrop:none;--c-ble:#008855;--c-ble-bg:rgba(0,136,85,0.15);--c-wifi:#00cc66;--c-wifi-bg:rgba(0,204,102,0.1);--c-rand:#008855;--c-known:#00cc66;--c-away:#ffcc00;--c-away-bg:rgba(255,204,0,0.1);--c-ap:#00cc66;--c-alert:#ffcc00;--c-alert-bg:rgba(255,204,0,0.1);--c-ok:#00cc66;--c-err:#ff4444;--c-err-bg:rgba(255,68,68,0.1)}
      [data-theme="cyber"] body{font-family:'Courier New',monospace;text-shadow:0 0 2px rgba(0,255,0,0.7)}
      .theme-toggle .terminal{opacity:0;transform:scale(0);stroke:var(--acc);fill:none}
      [data-theme="cyber"] .theme-toggle .sun{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="cyber"] .theme-toggle .moon{opacity:0;transform:rotate(90deg) scale(0)}
      [data-theme="cyber"] .theme-toggle .terminal{opacity:1;transform:scale(1)}
      .page-tabs{display:flex;gap:4px;background:var(--surf-hover);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:4px;border-radius:12px;border:1px solid var(--bord)}
      .page-tab-btn{padding:8px 16px;background:transparent;border:1px solid transparent;border-radius:9px;cursor:pointer;color:var(--mut);font-size:13px;font-weight:600;transition:all 0.2s;white-space:nowrap}
      .page-tab-btn.active{background:var(--surf);color:var(--txt);box-shadow:inset 0 1px 0 rgba(255,255,255,0.06),0 3px 8px -3px rgba(0,0,0,0.5);border:1px solid var(--bord)}
      .page-tab-btn:hover:not(.active){color:var(--acc)}
      @media(max-width:440px){.page-tabs{gap:2px;justify-content:space-between}.page-tab-btn{padding:6px 8px;font-size:11px}}
      .page-tab{display:none}
      .page-tab.active{display:block}
      #page-results #r{min-height:calc(100vh - 200px);overflow-y:auto}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
      #data-table{width:100%;border-collapse:collapse;font-size:13px}
      #data-table th{position:sticky;top:0;background:var(--surf);border-bottom:2px solid var(--bord);padding:9px 12px;text-align:left;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);cursor:pointer;user-select:none;white-space:nowrap}
      #data-table th:hover{color:var(--acc)}
      #data-table th .sort-arrow{margin-left:4px;font-size:9px}
      #data-table td{padding:9px 12px;border-bottom:1px solid var(--bord);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}
      #data-table tr:hover{background:var(--accbg)}
      .data-header{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
      .data-header select{width:auto;min-width:160px;padding:9px 34px 9px 13px;font-size:13px;border-radius:9px}
      .data-header input[type="text"]{flex:1;min-width:120px;padding:9px 13px;font-size:13px;border-radius:9px}
      .data-pager{display:flex;align-items:center;justify-content:center;gap:12px;margin-top:12px;font-size:12px;color:var(--mut)}
      .data-pager button{padding:6px 12px}
      .rssi-good{color:var(--succ)}.rssi-mid{color:var(--warn)}.rssi-bad{color:var(--dang)}
      .rand-yes{color:var(--warn);font-weight:600}
      .data-empty{text-align:center;padding:40px 20px;color:var(--mut);font-size:14px}
      html.theme-switching *,html.theme-switching *::before,html.theme-switching *::after{transition:none!important}
      /* ===== Results design system — continuity with System tab ===== */
      /* block components self-space so they read right as direct children of #r (sorted result types) */
      .res-hero,.res-card,.res-section,.res-callout{margin-bottom:14px}
      .res-list{display:flex;flex-direction:column;gap:12px}
      .res-list>.res-card,.res-section-body>.res-card{margin-bottom:0}
      .res-hero{background:linear-gradient(180deg,var(--surf-hover),var(--surf));border:1px solid var(--bord);border-radius:12px;padding:18px 20px;box-shadow:inset 0 1px 0 rgba(255,255,255,0.05),0 6px 18px -12px rgba(0,0,0,0.6);position:relative;overflow:hidden}
      .res-hero::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(180deg,var(--bord-focus),transparent 55%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;opacity:0.5;pointer-events:none}
      .res-hero-top{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap}
      .res-hero-title{font-size:15px;font-weight:700;letter-spacing:-0.01em;color:var(--txt);display:inline-flex;align-items:center;gap:8px;line-height:1.2}
      .res-hero-title svg{width:17px;height:17px;stroke:var(--acc);fill:none;flex-shrink:0}
      .res-scanning{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;color:var(--acc);animation:pulse 1.5s ease-in-out infinite}
      .res-scanning::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--acc);box-shadow:0 0 8px var(--acc)}
      .res-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px}
      .res-stat{background:var(--accbg);border:1px solid var(--bord);border-radius:9px;padding:11px 13px}
      .res-stat-lab{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--mut);margin-bottom:6px;display:flex;align-items:center;gap:6px}
      .res-stat-val{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-variant-numeric:tabular-nums;font-size:22px;font-weight:700;letter-spacing:-0.02em;color:var(--txt);line-height:1}
      .res-stat-val small{font-size:12px;color:var(--mut);font-weight:500;margin-left:2px}
      .res-stat.danger .res-stat-val{color:var(--dang)}
      .res-stat.warn .res-stat-val{color:var(--warn)}
      .res-stat.ok .res-stat-val{color:var(--succ)}
      /* item card */
      .res-card{background:var(--surf);border:1px solid var(--bord);border-radius:11px;padding:16px 18px 16px 20px;transition:border-color .2s,transform .2s,box-shadow .2s;position:relative;overflow:hidden}
      .res-card:hover{border-color:var(--bord-focus);transform:translateY(-1px);box-shadow:var(--glow)}
      .res-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:transparent;transition:background .2s}
      .res-card.acc::before{background:var(--acc)}
      .res-card.alert::before{background:var(--warn)}
      .res-card.danger::before{background:var(--dang)}
      .res-card.ok::before{background:var(--succ)}
      .res-card.ble::before{background:var(--c-ble)}
      .res-card.target{border-color:var(--acc);background:var(--accbg);box-shadow:var(--glow)}
      .res-card.target::before{background:var(--acc)}
      /* 3-zone horizontal band: identity | meta (fills the middle) | metric */
      .res-row-main{display:flex;align-items:center;gap:10px 20px;flex-wrap:wrap}
      .res-card-head{display:flex;justify-content:space-between;align-items:center;gap:12px 20px;flex-wrap:wrap}
      .res-id{min-width:0;display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex-shrink:0}
      .res-meta{flex:1 1 160px;min-width:0;display:flex;align-items:center;gap:8px 18px;flex-wrap:wrap;font-size:14px;color:var(--mut);line-height:1.4}
      .res-meta>span{display:inline-flex;align-items:center;gap:6px}
      .res-meta strong{color:var(--txt);font-weight:600}
      .res-mac{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:15.5px;font-weight:700;letter-spacing:0.02em;color:var(--txt);display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;word-break:break-all}
      .res-mac.acc{color:var(--acc)}
      .res-mac.warn{color:var(--warn)}
      .res-line{font-size:14px;color:var(--mut);line-height:1.5}
      .res-line strong{color:var(--txt);font-weight:600}
      .res-metric{text-align:right;flex-shrink:0;display:flex;flex-direction:column;gap:2px;margin-left:auto}
      .res-metric-val{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--txt);line-height:1.05;letter-spacing:-0.01em}
      .res-metric-val small{font-size:13px;color:var(--mut);font-weight:500;margin-left:1px}
      .res-metric-lab{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--mut)}
      /* mini KV grid inside a card */
      .res-kvs{display:grid;grid-template-columns:repeat(auto-fit,minmax(116px,1fr));gap:10px;margin-top:14px}
      .res-kv{background:var(--bg);border:1px solid var(--bord);border-radius:9px;padding:11px 13px}
      .res-kv.danger{border-color:var(--dang)}
      .res-kv-lab{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.04em;color:var(--mut);margin-bottom:6px;line-height:1.2}
      .res-kv-val{font-size:18px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--txt);line-height:1.15}
      .res-kv-val.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}
      .res-kv-val.sm{font-size:14px;font-weight:600}
      /* badges */
      .res-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:0.03em;text-transform:uppercase;border:1px solid var(--bord);background:var(--surf);color:var(--mut);white-space:nowrap;vertical-align:middle;line-height:1.5}
      .res-badge.acc{color:var(--acc);border-color:var(--acc);background:var(--accbg)}
      .res-badge.known{color:#fff;background:var(--c-known);border-color:var(--c-known)}
      .res-badge.target{color:#fff;background:var(--acc);border-color:var(--acc)}
      .res-badge.danger{color:var(--dang);border-color:var(--dang);background:var(--c-err-bg)}
      .res-badge.warn{color:var(--warn);border-color:var(--warn);background:var(--c-away-bg)}
      .res-badge.ok{color:var(--succ);border-color:var(--succ);background:var(--accbg)}
      .res-badge.ble{color:var(--c-ble);border-color:var(--c-ble);background:var(--c-ble-bg)}
      .res-badge.wifi{color:var(--c-wifi);border-color:var(--c-wifi);background:var(--c-wifi-bg)}
      .res-badge.muted{color:#fff;background:var(--mut);border-color:var(--mut)}
      /* tags (SSIDs / probes) */
      .res-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:11px;align-items:center}
      .res-tags-lab{font-size:11px;font-weight:600;color:var(--mut);margin-right:2px}
      .res-tag{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:500;border:1px solid var(--bord);background:var(--bg);color:var(--txt);white-space:nowrap}
      .res-tag.away{border-style:dashed;border-color:var(--c-away);color:var(--c-away);background:var(--c-away-bg)}
      .res-tag sup{font-size:8px;opacity:.7;margin-left:2px}
      /* note / reason line */
      .res-note{margin-top:12px;padding:10px 12px;background:var(--bg);border:1px solid var(--bord);border-left:3px solid var(--acc);border-radius:8px;font-size:12.5px;color:var(--txt);line-height:1.5}
      .res-note.warn{border-left-color:var(--warn);color:var(--warn)}
      .res-note.danger{border-left-color:var(--dang)}
      .res-note-lab{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin-right:6px}
      /* sub meta line */
      .res-sub{font-size:12px;color:var(--mut);margin-top:9px;line-height:1.5}
      .res-sub strong{color:var(--txt);font-weight:600}
      /* nested source rows (attack sources, mac list) */
      .res-rows{margin-top:11px;padding:11px 12px;background:var(--bg);border:1px solid var(--bord);border-radius:8px}
      .res-rows-lab{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin-bottom:8px}
      .res-row{display:flex;justify-content:space-between;align-items:center;gap:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--txt);padding:6px 0;border-bottom:1px solid var(--bord)}
      .res-row:last-child{border-bottom:none;padding-bottom:0}
      .res-row-meta{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:11px;color:var(--mut);white-space:nowrap}
      .res-more{padding:8px;text-align:center;color:var(--mut);font-size:11px;font-style:italic}
      /* collapsible section (Node Reports, Baseline devices, MAC lists) */
      .res-section{background:var(--surf);border:1px solid var(--bord);border-radius:12px;padding:14px 16px;box-shadow:var(--shad)}
      .res-section>summary{cursor:pointer;list-style:none;user-select:none;display:flex;align-items:center;gap:9px;font-size:13.5px;font-weight:700;color:var(--acc)}
      .res-section>summary::-webkit-details-marker{display:none}
      .res-section>summary .res-caret{transition:transform .2s;font-size:11px;display:inline-block}
      .res-section[open]>summary .res-caret{transform:rotate(90deg)}
      .res-section-body{margin-top:14px;display:flex;flex-direction:column;gap:10px}
      /* callout banner (no mesh, impossible, etc.) */
      .res-callout{padding:16px 18px;border-radius:12px;border:1px solid var(--bord);background:var(--surf);display:flex;gap:13px;align-items:flex-start}
      .res-callout.danger{border-color:var(--dang);background:var(--c-err-bg)}
      .res-callout.warn{border-color:var(--warn);background:var(--c-alert-bg)}
      .res-callout svg{width:22px;height:22px;flex-shrink:0;stroke-width:2;fill:none;margin-top:1px}
      .res-callout.danger svg{stroke:var(--dang)}
      .res-callout.warn svg{stroke:var(--warn)}
      .res-callout-title{font-size:14px;font-weight:700;margin-bottom:4px}
      .res-callout.danger .res-callout-title{color:var(--dang)}
      .res-callout.warn .res-callout-title{color:var(--warn)}
      .res-callout-body{font-size:12.5px;color:var(--txt);line-height:1.5}
      /* empty state */
      .res-empty{text-align:center;padding:40px 20px;color:var(--mut);font-size:14px;display:flex;flex-direction:column;align-items:center;gap:12px}
      .res-empty svg{width:34px;height:34px;stroke:var(--mut);fill:none;opacity:.45}
      /* CTA (open in maps) */
      .res-cta{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 18px;margin-top:4px;background:linear-gradient(135deg,var(--acc),var(--acch));border:1px solid var(--acc);border-radius:9px;color:#fff;text-decoration:none;font-weight:600;font-size:13px;box-shadow:var(--glow);transition:filter .2s}
      .res-cta:hover{filter:brightness(1.08)}
      .res-cta svg{width:15px;height:15px;stroke:currentColor;fill:none}
      /* position hero (triangulation estimate) */
      .res-coord{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}
      .res-coord .res-kv-val{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:15px}
      /* results header toolbar (Sort / Clear / Privacy) — aligned to card system */
      .res-toolbar{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
      .res-toolbar-lab{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--mut)}
      .res-toolbar select#sortBy{width:auto;min-width:160px;padding:9px 36px 9px 13px;font-size:13px;font-weight:600;border-radius:9px;box-shadow:none;background-position:right 13px center}
      .res-toolbar .btn{padding:9px 13px;font-size:13px;line-height:1;border-radius:9px}
      .res-toolbar .btn svg{width:11px;height:15px}
      @media(max-width:600px){.res-stats{grid-template-columns:1fr 1fr}.res-kvs{grid-template-columns:1fr 1fr}.res-toolbar{width:100%}.res-toolbar select#sortBy{flex:1 1 auto}#deviceScanHeader .res-stats[data-n="3"]{grid-template-columns:repeat(3,1fr);gap:7px}#deviceScanHeader .res-stats[data-n="3"] .res-stat{padding:9px 8px}#deviceScanHeader .res-stats[data-n="3"] .res-stat-val{font-size:16px}}
    </style>
    <script>
      let toggleHistory=[];
      function toggleTheme(){const e=document.documentElement,t=e.getAttribute('data-theme'),now=Date.now();e.classList.add('theme-switching');requestAnimationFrame(function(){requestAnimationFrame(function(){e.classList.remove('theme-switching');});});toggleHistory.push(now);toggleHistory=toggleHistory.filter(time=>now-time<2000);if(t==='cyber'){const n=localStorage.getItem('prevTheme')||'light';e.setAttribute('data-theme',n);localStorage.setItem('theme',n);localStorage.removeItem('cyberMode');localStorage.removeItem('prevTheme');toggleHistory=[];return}if(toggleHistory.length>=4&&!localStorage.getItem('cyberMode')){localStorage.setItem('prevTheme',t);e.setAttribute('data-theme','cyber');localStorage.setItem('theme','cyber');localStorage.setItem('cyberMode','1');toggleHistory=[];return}const n='dark'===t?'light':'dark';e.setAttribute('data-theme',n);localStorage.setItem('theme',n)}
      (function(){const e=localStorage.getItem('theme');e?document.documentElement.setAttribute('data-theme',e):document.documentElement.setAttribute('data-theme','light')})();
    </script>
  </head>
  <body>
    <!-- Onboarding disclaimer overlay -->
    <div id="ob-overlay" style="display:none;position:fixed;inset:0;z-index:10000;background:#0b0e14;align-items:center;justify-content:center;flex-direction:column">
      <div style="width:min(460px,92vw);max-height:90vh;display:flex;flex-direction:column">
        <div style="text-align:center;padding:32px 0 20px;flex-shrink:0">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:12px"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/><path d="M8 12a4 4 0 0 0 4 4M16 12a4 4 0 0 0-4-4" opacity="0.5"/></svg>
          <div style="font-size:22px;font-weight:700;color:#e8ecf0;letter-spacing:-0.02em">Welcome to AntiHunter</div>
          <div style="font-size:13px;color:#6878a0;margin-top:4px">WiFi/BLE Detection Node</div>
        </div>
        <div id="ob-scroll" style="flex:1;overflow-y:auto;padding:0 24px 16px;-webkit-overflow-scrolling:touch">
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Authorized Use Only</div><div style="font-size:13px;color:#8898b8;line-height:1.5">For use on networks and systems you own or have explicit written permission to assess. Comply with all local privacy, radio, and telecom laws.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#c09040" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">No Warranty</div><div style="font-size:13px;color:#8898b8;line-height:1.5">Provided "AS IS" without warranty of any kind. Detection accuracy is not guaranteed. Do not rely on this for safety-critical decisions.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Privacy and Data</div><div style="font-size:13px;color:#8898b8;line-height:1.5">All data is stored locally on your device. You are responsible for securing collected data and complying with data protection laws (e.g., GDPR) in your jurisdiction.</div></div>
          </div>
          <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin-bottom:10px">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#60a0e0" stroke-width="2" stroke-linecap="round" style="flex-shrink:0;margin-top:1px"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
            <div><div style="font-size:14px;font-weight:600;color:#e8ecf0;margin-bottom:4px">Your Responsibility</div><div style="font-size:13px;color:#8898b8;line-height:1.5">By continuing, you accept full responsibility for your actions and agree to indemnify the authors and contributors against any claims arising from your use.</div></div>
          </div>
        </div>
        <div style="padding:12px 24px 28px;flex-shrink:0;text-align:center">
          <div id="ob-hint" style="font-size:11px;color:#6878a0;margin-bottom:10px;transition:opacity 0.3s">Scroll to review all sections</div>
          <button id="ob-btn" disabled onclick="obAccept()" style="width:100%;padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.06);color:#6878a0;font-size:15px;font-weight:600;cursor:not-allowed;transition:all 0.5s cubic-bezier(0.4,0,0.2,1)">Continue</button>
        </div>
      </div>
    </div>
    <style>
      @keyframes ob-glow{0%,100%{box-shadow:0 0 0 0 rgba(64,180,100,0.4)}50%{box-shadow:0 0 24px 4px rgba(64,180,100,0.15)}}
      #ob-btn.ready{background:linear-gradient(135deg,#38a860,#2e8c50);border-color:#38a860;color:#fff;cursor:pointer;animation:ob-glow 2.5s ease-in-out infinite}
      #ob-btn.ready:hover{filter:brightness(1.15);transform:scale(1.02)}
      #ob-scroll::-webkit-scrollbar{width:4px}
      #ob-scroll::-webkit-scrollbar-track{background:transparent}
      #ob-scroll::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.12);border-radius:2px}
    </style>
    <script>
    (function(){
      var ov=document.getElementById('ob-overlay');
      var sc=document.getElementById('ob-scroll');
      var bt=document.getElementById('ob-btn');
      var hn=document.getElementById('ob-hint');
      function chkScroll(){
        if(sc.scrollTop+sc.clientHeight>=sc.scrollHeight-10){
          bt.disabled=false;bt.classList.add('ready');hn.style.opacity='0';
        }
      }
//    fetch('/api/onboarding').then(function(r){return r.json()}).then(function(d){
//      if(!d.accepted){ov.style.display='flex';setTimeout(chkScroll,100)}
//    }).catch(function(){ov.style.display='flex';setTimeout(chkScroll,100)});
//    sc.addEventListener('scroll',chkScroll);
//    window.obAccept=function(){
//      if(bt.disabled)return;
//      fetch('/api/onboarding',{method:'POST'}).then(function(){
//        ov.style.opacity='0';ov.style.transition='opacity 0.4s';
//        setTimeout(function(){ov.style.display='none'},400);
//      });
//    };
    })();
    </script>
    <div id="toast"></div>
    <div class="header">
      <div class="header-bar">
        <h1><svg class="brand-shield" viewBox="3 1 18 22" fill="none" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span class="wm"><b>Anti</b>Hunter</span></h1>
        <div class="statx-ticker"><div class="statx-track" id="statxTrack">
            <div class="status-item idle" id="scanStatus">Idle</div>
              <div class="status-item" id="gpsStatus">GPS</div>
              <div class="status-item" id="meshTxStatus" style="display:none;cursor:pointer;" onclick="cancelMeshDrain()" title="Click to cancel pending mesh TX">Mesh TX 0/0</div>
              <div class="status-item" id="sentStatusHdr" onclick="sentinelToggleHdr()" style="cursor:pointer;display:none;" title="Click to toggle Sentinel">SENTINEL</div>
        </div></div>
        <div class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
          </svg>
          <svg class="moon" viewBox="0 0 24 24" fill="currentColor">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
          <svg class="terminal" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
            <polyline points="6 8 10 12 6 16"/>
            <line x1="12" y1="12" x2="18" y2="12"/>
          </svg>
        </div>
        <a class="btn danger" href="/stop" id="stopAllBtn" onclick="return stopScan(event)" style="display:none;">STOP</a>
      </div>
      <div class="page-tabs">
        <div class="page-tab-btn active" onclick="switchPage('scan')">Scan</div>
        <div class="page-tab-btn" onclick="switchPage('results')">Results</div>
        <div class="page-tab-btn" onclick="switchPage('system')">System</div>
        <div class="page-tab-btn" onclick="switchPage('data')">Data</div>
        <div class="page-tab-btn" onclick="switchPage('detect')">Sentinel</div>
      </div>
    </div>
    <script>
      (function(){
        var N=14,BUF={},PREV={},
            COL={wifiFrames:'#4c8dff',bleFrames:'#6ba5ff',uniqueDevices:'#37d39b',temperature:'#f5b547'},
            RATE={wifiFrames:1,bleFrames:1};
        window.pushSpark=function(key,val){
          if(!isFinite(val))return;
          if(RATE[key]){var p=PREV[key];PREV[key]=val;if(p===undefined)return;val=Math.max(0,val-p);}
          var b=BUF[key]||(BUF[key]=[]);b.push(val);if(b.length>N)b.shift();draw(key,b);
        };
        function draw(key,b){
          var svg=document.querySelector('.stat-spark[data-spark="'+key+'"]');
          if(!svg)return;
          if(b.length<2){svg.innerHTML='';return;}
          var W=60,H=22,pad=2,n=b.length,
              mn=Math.min.apply(null,b),mx=Math.max.apply(null,b),rng=(mx-mn)||1,dx=W/(n-1),
              col=COL[key]||'var(--acc)',d='',lx=0,ly=0;
          for(var i=0;i<n;i++){
            var x=i*dx,y=H-pad-((b[i]-mn)/rng)*(H-2*pad);
            d+=(i?' L':'M')+x.toFixed(1)+' '+y.toFixed(1);
            if(i===n-1){lx=x;ly=y;}
          }
          svg.setAttribute('viewBox','0 0 '+W+' '+H);
          svg.setAttribute('preserveAspectRatio','none');
          svg.innerHTML='<path d="'+d+' L'+W+' '+H+' L0 '+H+' Z" fill="'+col+'" opacity="0.12"/>'+
            '<path d="'+d+'" fill="none" stroke="'+col+'" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'+
            '<circle cx="'+lx.toFixed(1)+'" cy="'+ly.toFixed(1)+'" r="1.6" fill="'+col+'"/>';
        }
      })();
    </script>
    <div class="container">
      <div class="page-tab active" id="page-scan">

      <!-- Scanning & Targets + Detection Grid -->
      <div class="grid-2" style="margin-bottom:16px;">
        
        <!-- Scanning & Targets -->
        <div class="card">
          <div class="card-header" onclick="toggleCollapse('scanCard')">
            <h3>Scanning & Targets</h3>
            <span class="collapse-icon open" id="scanCardIcon">▶</span>
          </div>
          <div class="card-body" id="scanCardBody">
            
            <!-- Target List -->
            <details open>
              <summary style="cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;"><span>▶</span> Target List</summary>
              <form id="f" method="POST" action="/save">
                <textarea id="list" name="list" placeholder="MAC, OUI, or SSID (one per line)&#10;AA:BB:CC:DD:EE:FF&#10;AA:BB:CC&#10;MyHomeWiFi" rows="3"></textarea>
                <div id="targetCount" style="margin:4px 0 8px;color:var(--mut);font-size:11px;">0 targets</div>
                <div style="display:flex;gap:8px;">
                  <button class="btn primary" type="submit">Save</button>
                  <a class="btn alt" href="/export" download="targets.txt" data-ajax="false">Export</a>
                </div>
              </form>
            </details>
            
            <!-- Allowlist -->
            <details style="margin-top:12px;">
              <summary style="cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;"><span>▶</span> Allow List</summary>
              <form id="af" method="POST" action="/allowlist-save">
                <textarea id="wlist" name="list" placeholder="DD:EE:FF&#10;11:22:33:44:55:66" rows="3"></textarea>
                <div id="allowlistCount" style="margin:4px 0 8px;color:var(--mut);font-size:11px;">0 allowlisted</div>
                <div style="display:flex;gap:8px;">
                  <button class="btn primary" type="submit">Save</button>
                  <a class="btn alt" href="/allowlist-export" download="allowlist.txt" data-ajax="false">Export</a>
                </div>
              </form>
            </details>
            
            <!-- Scan Controls -->
            <form id="s" method="POST" action="/scan">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                <div>
                  <label style="font-size:11px;">Mode</label>
                  <select name="mode">
                    <option value="0">WiFi</option>
                    <option value="1">BLE</option>
                    <option value="2" selected>WiFi+BLE</option>
                  </select>
                </div>
                <div>
                  <label style="font-size:11px;">Duration (s)</label>
                  <input type="number" name="secs" min="0" max="86400" value="60">
                </div>
              </div>
              
              <div style="display:flex;gap:16px;margin-bottom:12px;">
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;">
                  <input type="checkbox" id="forever" name="forever" value="1">Forever
                </label>
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;">
                  <input type="checkbox" id="triangulate" name="triangulate" value="1">Triangulate
                </label>
              </div>
              
              <div id="triangulateOptions" style="display:none;margin-bottom:8px;">
                <input type="text" name="targetMac" placeholder="Target MAC">
                <label style="font-size:11px;margin-top:8px;">RF Environment</label>
                <select name="rfEnv" id="rfEnvSelect">
                  <option value="0">Open Sky</option>
                  <option value="1">Suburban</option>
                  <option value="2" selected>Indoor</option>
                  <option value="3">Indoor Dense</option>
                  <option value="4">Industrial</option>
                </select>

                <label style="font-size:11px;margin-top:12px;display:block;">Distance Tuning</label>
                <div style="margin-bottom:6px;">
                  <label style="font-size:10px;color:var(--mut);">WiFi: <span id="wifiPwrDisplay">1.0x</span></label>
                  <input type="range" name="wifiPwr" id="wifiPwrSlider" min="0.1" max="5.0" step="0.1" value="1.0"
                        oninput="document.getElementById('wifiPwrDisplay').innerText = this.value + 'x'"
                        style="width:100%;">
                </div>
                <div style="margin-bottom:4px;">
                  <label style="font-size:10px;color:var(--mut);">BLE: <span id="blePwrDisplay">1.0x</span></label>
                  <input type="range" name="blePwr" id="blePwrSlider" min="0.1" max="5.0" step="0.1" value="1.0"
                        oninput="document.getElementById('blePwrDisplay').innerText = this.value + 'x'"
                        style="width:100%;">
                </div>
                <p style="font-size:9px;color:var(--mut);margin:4px 0 0 0;"><1.0 closer | >1.0 farther</p>
              </div>
              
              <button class="btn primary" type="submit" style="width:100%;">Start Scan</button>
            </form>
          </div>
        </div>
        
        <!-- Detection & Analysis -->
        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detectionCard')">
            <h3>Detection & Analysis</h3>
            <span class="collapse-icon open" id="detectionCardIcon">▶</span>
          </div>
          <div class="card-body" id="detectionCardBody"> <!-- Add this wrapper -->
            <form id="sniffer" method="POST" action="/sniffer">
              <label>Method</label>
              <select name="detection" id="detectionMode">
                <option value="device-scan" selected>Device Discovery</option>
                <option value="baseline">Baseline Anomaly Sniffer</option>
                <option value="randomization-detection">Randomized Device Tracer</option>
                <option value="deauth">Deauthentication Attack Detection</option>
                <option value="drone-detection">Drone RID Detection (WiFi)</option>
                <!-- <option value="counter-surveil">Counter-Surveillance / Find My (BLE)</option> hidden: co-presence/follower engine needs mobile validation before beta -->
                <option value="probe-scan">Probe Request Scanner</option>
              </select>

              <div id="probeScanModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="probeScanMode" name="probeScanMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
                <label style="font-size:11px;margin-top:6px;display:flex;align-items:center;gap:6px;"><input type="checkbox" name="broadcastAll" value="1">Broadcast All Probes (mesh)</label>
              </div>
              <div id="randomizationModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="randomizationMode" name="randomizationMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
              </div>
              <div id="deviceScanModeControls" style="display:none;margin-top:10px;">
                <label style="font-size:11px;">Scan Mode</label>
                <select id="deviceScanMode" name="deviceScanMode">
                  <option value="0">WiFi Only</option>
                  <option value="2" selected>WiFi + BLE</option>
                  <option value="1">BLE Only</option>
                </select>
                <label style="font-size:11px;margin-top:6px;display:flex;align-items:center;gap:6px;"><input type="checkbox" name="captureProbes" value="1">Capture Probes</label>
              </div>
              <div id="standardDurationControls" style="margin-top:10px;">
                <div style="display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end;">
                  <div>
                    <label style="font-size:11px;">Duration (s)</label>
                    <input type="number" name="secs" min="0" max="86400" value="60" id="detectionDuration">
                  </div>
                  <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;">
                    <input type="checkbox" id="forever3" name="forever" value="1">Forever
                  </label>
                </div>
              </div>
              
              <div id="baselineConfigControls" style="display:none;margin-top:10px;">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:11px;">RSSI</label>
                    <select id="baselineRssiThreshold" name="rssiThreshold">
                      <option value="-40">-40</option>
                      <option value="-50">-50</option>
                      <option value="-60" selected>-60</option>
                      <option value="-70">-70</option>
                      <option value="-80">-80</option>
                    </select>
                  </div>
                  <div>
                    <label style="font-size:11px;">Baseline</label>
                    <select id="baselineDuration" name="baselineDuration">
                      <option value="300" selected>5m</option>
                      <option value="600">10m</option>
                      <option value="900">15m</option>
                    </select>
                  </div>
                </div>
                
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:11px;">RAM Cache (Non-SD defaults to 1500)</label>
                    <input type="number" id="baselineRamSize" name="ramCacheSize" min="200" max="500" value="400" style="padding:6px;">
                  </div>
                  <div>
                    <label style="font-size:11px;">SD Device Storage</label>
                    <input type="number" id="baselineSdMax" name="sdMaxDevices" min="1000" max="100000" value="50000" step="1000" style="padding:6px;">
                  </div>
                </div>
                
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:8px;">
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Time a device must be unseen before marked as disappeared from baseline">Marked Absent (s)</label>
                    <input type="number" id="absenceThreshold" min="30" max="600" value="120" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Window after disappearance during which reappearance triggers an anomaly alert">Seen Reappear (s)</label>
                    <input type="number" id="reappearanceWindow" min="60" max="1800" value="300" style="padding:4px;font-size:11px;">
                  </div>
                  <div>
                    <label style="font-size:10px;color:var(--mut);" title="Minimum RSSI change in dBm to flag as significant signal strength variation">RSSI Variation dB</label>
                    <input type="number" id="rssiChangeDelta" min="5" max="50" value="20" style="padding:4px;font-size:11px;">
                  </div>
                </div>
                
                <label style="font-size:11px;">Monitor (s)</label>
                <input type="number" name="secs" min="0" max="86400" value="300" id="baselineMonitorDuration" style="margin-bottom:8px;">
                <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:12px;padding-bottom:8px;color:var(--txt);">
                  <input type="checkbox" id="foreverBaseline" name="forever" value="1" style="width:auto;margin:0;">
                  <span>Forever</span>
                </label>
              </div>
              
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;">
                <button class="btn primary" type="submit" id="startDetectionBtn" style="flex:1;min-width:80px;">Start</button>
                <a class="btn alt" href="/sniffer-cache" data-ajax="false" id="cacheBtn" style="display:none;">Cache</a>
                <button class="btn alt" type="button" onclick="resetBaseline()" style="display:none;" id="resetBaselineBtn">Reset</button>
                <button type="button" class="btn" id="clearOldBtn" style="display:none;" onclick="clearOldIdentities()">Clear Old</button>
                <button type="button" class="btn" id="resetRandBtn" style="display:none;" onclick="resetRandomizationDetection()">Reset All</button>
              </div>
             
            </form>
          </div>
        </div>
      </div>
      </div>

      <div class="page-tab" id="page-results">
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:12px;flex-wrap:wrap;">
          <h3 style="margin:0;">Scan Results</h3>
          <div class="res-toolbar">
            <span class="res-toolbar-lab">Sort</span>
            <select id="sortBy" onchange="applySorting()">
              <option value="default">Default</option>
              <option value="rssi-desc">RSSI (Strongest)</option>
              <option value="rssi-asc">RSSI (Weakest)</option>
              <option value="confidence-desc">Confidence (High)</option>
              <option value="sessions-desc">Sessions (Most)</option>
              <option value="lastseen-asc">Last Seen (Recent)</option>
              <option value="name-asc">Name (A-Z)</option>
              <option value="type-asc">Type (WiFi/BLE)</option>
              <option value="channel-asc">Channel (Low-High)</option>
            </select>
            <button class="btn alt" type="button" onclick="toggleSortOrder()" title="Reverse sort"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="14" viewBox="0 0 10 14" fill="currentColor"><path d="M5 0L10 5H0Z"/><path d="M5 14L0 9H10Z"/></svg></button>
            <button class="btn alt" type="button" onclick="clearResults()">Clear</button>
            <button class="btn" id="privacyBtn" type="button" onclick="togglePrivacy()" style="white-space:nowrap;flex-shrink:0;"></button>
          </div>
        </div>
        <div id="baselineStatus" style="display:none;padding:12px;background:var(--surf);border:2px solid var(--acc);border-radius:8px;font-size:12px;margin-bottom:12px;">
          <div style="color:var(--mut);">No baseline data</div>
        </div>
        <div id="r" style="margin:0;">No scan data yet.</div>
      </div>
      </div>

      <div class="page-tab" id="page-system">

      <div class="card" style="margin-bottom:16px;">
          <h3>System Diagnostics</h3>
          <p class="card-sub">Live node telemetry · <span id="diagNodeId">--</span> · <span id="diagAge">live</span></p>
          <div class="tab-buttons">
            <div class="tab-btn active" onclick="switchTab('overview')">Overview</div>
            <div class="tab-btn" onclick="switchTab('hardware')">Hardware</div>
            <div class="tab-btn" onclick="switchTab('network')">Network</div>
          </div>
          <div id="overview" class="tab-content active">
            <div class="stat-grid">
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>Uptime</div><div class="stat-value" id="uptime">--:--:--</div></div>
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/></svg>WiFi Frames</div><div class="stat-value" id="wifiFrames">0</div><svg class="stat-spark" data-spark="wifiFrames"></svg></div>
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7l10 10-5 4V3l5 4L7 17"/></svg>BLE Frames</div><div class="stat-value" id="bleFrames">0</div><svg class="stat-spark" data-spark="bleFrames"></svg></div>
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/></svg>Target Hits</div><div class="stat-value" id="totalHits">0</div></div>
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/></svg>Unique Devices</div><div class="stat-value" id="uniqueDevices">0</div><svg class="stat-spark" data-spark="uniqueDevices"></svg></div>
              <div class="stat-item"><div class="stat-label"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0Z"/></svg>CPU Temp</div><div class="stat-value" id="temperature">--<small>°C</small></div><svg class="stat-spark" data-spark="temperature"></svg></div>
            </div>
          </div>
          <div id="hardware" class="tab-content"><div id="hardwareDiag">Loading...</div></div>
          <div id="network" class="tab-content"><div id="networkDiag">Loading...</div></div>
      </div>

    <div class="grid-2" style="margin-bottom:16px;">
      <div class="card">
        <h3>RF Settings</h3>
        <p class="card-sub">Signal filtering &amp; sensitivity profile</p>
        <div class="" id="detectionCardBody">
          <label style="font-size:11px;">Global RSSI Filter (dBm)</label>
          <div style="display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:12px;align-items:center;">
            <input type="range" id="globalRssiSlider" min="-100" max="-10" value="-95" 
                  oninput="document.getElementById('globalRssiValue').innerText = this.value + ' dBm'">
            <span id="globalRssiValue" style="font-size:12px;min-width:70px;">-95 dBm</span>
          </div>
          <p style="font-size:10px;color:var(--mut);margin-bottom:12px;">Filters weak signals (triangulation exempt)</p>

          <hr style="margin:12px 0;border:none;border-top:1px solid var(--bord);">

          <select id="rfPreset" onchange="updateRFPresetUI()">
            <option value="0">Relaxed (Stealthy, all ch)</option>
            <option value="1">Balanced (Default, all ch)</option>
            <option value="2">Aggressive (Fast, 1/6/11)</option>
            <option value="3">Custom</option>
          </select>
          
          <div id="customRFSettings" style="display:none;margin-top:10px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--mut);">WiFi Channel Time (ms)</label>
                <input type="number" id="wifiChannelTime" min="110" max="300" value="120" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--mut);">WiFi Scan Interval (ms)</label>
                <input type="number" id="wifiScanInterval" min="1000" max="10000" value="4000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
              <div>
                <label style="font-size:10px;color:var(--mut);">BLE Scan Duration (ms)</label>
                <input type="number" id="bleScanDuration" min="1000" max="5000" value="2000" style="padding:4px;font-size:11px;">
              </div>
              <div>
                <label style="font-size:10px;color:var(--mut);">BLE Scan Interval (ms)</label>
                <input type="number" id="bleScanInterval" min="1000" max="10000" value="2000" style="padding:4px;font-size:11px;">
              </div>
            </div>
            <div style="margin-bottom:8px;">
              <label style="font-size:10px;color:var(--mut);">WiFi Channels</label>
              <input type="text" id="wifiChannels" placeholder="1..14" value="1..14" style="padding:4px;font-size:11px;">
            </div>
          </div>
        </div>
        <button class="btn primary" type="button" onclick="saveRFConfig()" style="width:100%;margin-top:8px;">Save RF Settings</button>

        <hr style="margin:16px 0;border:none;border-top:1px solid var(--bord);">
        <div class="card-header" onclick="toggleCollapse('wifiApCard')" style="cursor:pointer;padding:0;margin-bottom:12px;border:none;background:none;box-shadow:none;">
            <h4 style="margin:0;font-size:13px;">WiFi Access Point</h4>
            <span class="collapse-icon" id="wifiApCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="wifiApCardBody" style="max-height:0;">
            <label style="font-size:11px;">SSID</label>
            <input type="text" id="apSsid" maxlength="32" placeholder="Antihunter" style="margin-bottom:8px;">
            
            <label style="font-size:11px;">Password</label>
            <input type="password" id="apPass" minlength="8" maxlength="63" placeholder="Min 8 characters" style="margin-bottom:8px;">

            <label style="font-size:11px;">Security</label>
            <select id="apAuth" style="margin-bottom:8px;">
              <option value="0">WPA2/WPA3 (default)</option>
              <option value="1">WPA2 only (more stable)</option>
            </select>

            <button class="btn primary" type="button" onclick="saveWiFiConfig()" style="width:100%;margin-top:8px;">Save WiFi Settings</button>
          </div>
        </div>

      <div class="card">
          <h3>Node Configuration</h3>
          <p class="card-sub">Identity &amp; mesh networking</p>
          <form id="nodeForm" method="POST" action="/node-id" novalidate>
            <label>Node ID</label>
            <input type="text" id="nodeId" name="id" minlength="2" maxlength="5" placeholder="AH01" pattern="^[A-Z0-9]{2,5}$" style="text-transform:uppercase;">
            <button class="btn primary" type="submit" style="margin-top:8px;width:100%;">Update</button>
          </form>
          
          <hr>
          
          <div style="margin-top:12px;">
            <label>Mesh Communications</label>
            <div style="display:flex;gap:8px;margin-bottom:12px;">
              <button class="btn" id="meshToggleBtn" onclick="toggleMesh()" style="flex:1;"></button>
            </div>
            
            <div id="meshControls" style="display:none;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <input type="checkbox" id="hbEnabledCb" onchange="toggleHb()" style="width:20px;height:20px;">
                <label style="margin:0;font-size:13px;cursor:pointer;" for="hbEnabledCb">Status Heartbeat</label>
              </div>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
                <input type="number" id="hbIntervalInput" min="1" max="60" step="1" value="10" style="flex:1;">
                <label style="margin:0;font-size:12px;color:var(--mut);white-space:nowrap;">min interval</label>
                <button class="btn" onclick="saveHbInterval()">Save</button>
              </div>
              <label>Mesh Send Interval (ms)</label>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;">
                <input type="number" id="meshInterval" min="1500" max="30000" step="100" value="5000" style="flex:1;">
                <button class="btn" onclick="saveMeshInterval()">Save</button>
              </div>

              <label title="Skip rebroadcasting same MAC over LoRa within this window. 0 = disable (every scan broadcasts every device). Default 300s.">Mesh Dedup TTL (sec, 0=off)</label>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px;">
                <input type="number" id="meshDedupTtl" min="0" max="3600" step="30" value="300" style="flex:1;">
                <button class="btn" onclick="saveDedupTtl()">Save</button>
                <button class="btn alt" onclick="clearDedup()">Clear Cache</button>
              </div>
              <div id="dedupCacheInfo" style="font-size:11px;color:var(--mut);margin-bottom:6px;">Cache: 0 MACs tracked</div>
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:12px;cursor:pointer;" title="ON: subsequent scans send only devices not already sent this session (until Clear Cache). OFF: every scan re-broadcasts all devices it sees.">
                <input type="checkbox" id="meshSessionDedup" onchange="saveSessionDedup()" style="width:auto;">
                Session dedup — send only NEW devices across scans
              </label>

              <div style="display:flex;gap:8px;">
                <a class="btn alt" href="/mesh-test" data-ajax="true" style="flex:1;">Test</a>
                <a class="btn" href="/gps" data-ajax="false" style="flex:1;">GPS</a>
              </div>
            </div>
          </div>

          <hr>

          <div style="margin-top:12px;">
            <label>Vibration Sensor Alerts</label>
            <div style="display:flex;gap:8px;margin-bottom:4px;">
              <button class="btn" id="vibToggleBtn" onclick="toggleVibration()" style="flex:1;"></button>
            </div>
            <div style="font-size:10px;color:var(--mut);">Controls mesh broadcast alerts when vibration is detected</div>
          </div>
        </div>
      </div>

      <!-- Secure Data Destruction -->
      <div class="card">
        <div class="card-header" onclick="toggleCollapse('secureDataCard')">
          <h3>Secure Data Destruction</h3>
          <span class="collapse-icon" id="secureDataCardIcon">▶</span>
        </div>
        <div class="card-body collapsed" id="secureDataCardBody">
          <div class="banner">WARNING: Permanent data wipe — no recovery</div>

          <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">
            <span class="psk-badge unset" id="erasePskBadge">CHECKING...</span>
            <span class="psk-badge tamper" id="eraseStateBadge" style="display:none">IDLE</span>
          </div>

          <div style="margin-top:8px">
            <label class="field-name" style="font-size:11px;font-weight:700;display:block;margin-bottom:2px;text-transform:uppercase;letter-spacing:.04em">Authorization</label>
            <label class="field-hint" id="eraseConfirmHint" style="font-size:10px;color:var(--mut);display:block;margin-bottom:6px">Type WIPE_ALL_DATA exactly</label>
            <input type="text" id="eraseConfirm" placeholder="WIPE_ALL_DATA" autocomplete="off">
          </div>

          <button class="btn danger" type="button" onclick="requestErase()" style="width:100%;margin-top:10px">WIPE NOW</button>
          <button class="btn alt" type="button" onclick="cancelErase()" id="eraseAbortBtn" style="width:100%;margin-top:8px;display:none">ABORT TAMPER COUNTDOWN</button>

          <div id="eraseStatus" style="display:none;margin-top:10px;padding:8px;background:var(--surf);border:1px solid var(--bord);border-radius:6px;font-size:12px;"></div>

          <hr>

          <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
            <span style="font-weight:700;color:var(--acc);font-size:14px">Auto-Erase on Tampering</span>
            <span style="cursor:help;padding:2px 6px;background:var(--accbg);border:1px solid var(--acc);border-radius:4px;font-size:10px;" onclick="showAutoEraseHelp()" title="Click for help">?</span>
          </div>

          <label style="display:flex;align-items:center;gap:10px;margin-bottom:18px;cursor:pointer">
            <input type="checkbox" id="autoEraseEnabled" style="width:18px;height:18px;cursor:pointer">
            <span style="font-weight:600">Enable auto-erase when tamper detected</span>
          </label>

          <div class="subcard field-row" data-field="setupDelay">
            <div class="subcard-head">
              <span class="subcard-num">1</span>
              <div>
                <div class="subcard-title">Setup Period</div>
                <div class="subcard-sub">Grace period after enabling before tamper detection arms</div>
              </div>
            </div>
            <div class="chip-row">
              <span class="chip" data-value="30000">30s</span>
              <span class="chip" data-value="60000">1m</span>
              <span class="chip active" data-value="120000">2m</span>
              <span class="chip" data-value="300000">5m</span>
              <span class="chip" data-value="600000">10m</span>
            </div>
          </div>

          <div class="subcard field-row" data-field="autoEraseDelay">
            <div class="subcard-head">
              <span class="subcard-num">2</span>
              <div>
                <div class="subcard-title">Erase Countdown</div>
                <div class="subcard-sub">Time to cancel after tamper detected before wipe fires</div>
              </div>
            </div>
            <div class="chip-row">
              <span class="chip" data-value="10000">10s</span>
              <span class="chip active" data-value="30000">30s</span>
              <span class="chip" data-value="60000">1m</span>
              <span class="chip" data-value="120000">2m</span>
              <span class="chip" data-value="300000">5m</span>
            </div>
          </div>

          <div class="subcard field-row" data-field="autoEraseCooldown">
            <div class="subcard-head">
              <span class="subcard-num">3</span>
              <div>
                <div class="subcard-title">Trigger Cooldown</div>
                <div class="subcard-sub">Minimum gap before another tamper event can trigger erase</div>
              </div>
            </div>
            <div class="chip-row">
              <span class="chip" data-value="60000">1m</span>
              <span class="chip active" data-value="300000">5m</span>
              <span class="chip" data-value="600000">10m</span>
              <span class="chip" data-value="1800000">30m</span>
              <span class="chip" data-value="3600000">1h</span>
            </div>
          </div>

          <details style="margin-bottom:14px">
            <summary style="cursor:pointer;font-size:11px;font-weight:700;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;padding:6px 0">Advanced Sensitivity</summary>
            <div style="padding:10px 0 0 0">
              <div class="field-row" data-field="vibrationsRequired">
                <span class="field-name">Vibrations Required</span>
                <span class="field-hint">Count within window to trigger</span>
                <div class="chip-row">
                  <span class="chip" data-value="2">2</span>
                  <span class="chip active" data-value="3">3</span>
                  <span class="chip" data-value="4">4</span>
                  <span class="chip" data-value="5">5</span>
                </div>
              </div>

              <div class="field-row" data-field="detectionWindow" style="margin-bottom:0">
                <span class="field-name">Detection Window</span>
                <span class="field-hint">Time span for counting vibrations</span>
                <div class="chip-row">
                  <span class="chip" data-value="5000">5s</span>
                  <span class="chip" data-value="10000">10s</span>
                  <span class="chip active" data-value="20000">20s</span>
                  <span class="chip" data-value="30000">30s</span>
                  <span class="chip" data-value="60000">1m</span>
                </div>
              </div>
            </div>
          </details>

          <button class="btn primary" type="button" onclick="saveAutoEraseConfig()" style="width:100%;margin-top:6px">Save Auto-Erase Config</button>
          <div id="autoEraseStatus" style="margin-top:10px;padding:8px;border-radius:6px;font-size:11px;text-align:center;border:1px solid var(--bord);background:var(--surf)">DISABLED</div>
        </div>
      </div>

      <!-- Factory Wipe -->
      <div class="card">
        <div class="card-header" onclick="toggleCollapse('factoryWipeCard')">
          <h3>Factory Wipe</h3>
          <span class="collapse-icon" id="factoryWipeCardIcon">&#9654;</span>
        </div>
        <div class="card-body collapsed" id="factoryWipeCardBody">
          <div class="banner">WARNING: Wipes ALL SD data files + resets NVS to factory defaults. Device reboots.</div>
          <div style="margin-top:10px;font-size:11px;color:var(--mut);line-height:1.5;">
            Removes: probedb, probes, deauth, drones, vibrations, baseline, syslog, incidents, sentinel state, randdet identities, all logs.<br>
            Resets: AP creds, node ID, target list, allowlist, RF settings, mesh settings, auto-erase config — to defaults.
          </div>
          <label class="field-name" style="margin-top:12px;font-size:11px;font-weight:700;display:block;text-transform:uppercase;letter-spacing:.04em">Reset Scope</label>
          <select id="factoryResetTier" onchange="updateFactoryResetTier()" style="width:100%;margin-top:4px;margin-bottom:4px">
            <option value="full">Full Reset — wipe SD data + reset NVS config</option>
            <option value="config">Config Only — reset settings, keep captured data</option>
            <option value="data">Data Only — erase captured data, keep settings</option>
          </select>
          <div id="factoryResetScopeHint" style="font-size:10px;color:var(--mut);margin-bottom:6px;line-height:1.4">Wipes ALL SD data files + resets NVS to factory defaults. Device reboots.</div>
          <label class="field-name" style="margin-top:12px;font-size:11px;font-weight:700;display:block;text-transform:uppercase;letter-spacing:.04em">Authorization</label>
          <label class="field-hint" id="factoryWipeHint" style="font-size:10px;color:var(--mut);display:block;margin-bottom:6px">Type FACTORY_WIPE exactly</label>
          <input type="text" id="factoryWipeConfirm" placeholder="FACTORY_WIPE" autocomplete="off">
          <button class="btn danger" type="button" id="factoryWipeBtn" onclick="requestFactoryWipe()" style="width:100%;margin-top:8px;">WIPE EVERYTHING</button>
          <div id="factoryWipeStatus" style="display:none;margin-top:10px;padding:8px;background:var(--surf);border:1px solid var(--bord);border-radius:6px;font-size:12px;"></div>
        </div>
      </div>

      <!-- Battery Saver Mode -->
      <div class="card">
        <div class="card-header" onclick="toggleCollapse('batterySaverCard')">
          <h3>Battery Saver Mode</h3>
          <span class="collapse-icon" id="batterySaverCardIcon">&#9654;</span>
        </div>
        <div class="card-body collapsed" id="batterySaverCardBody">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
            <span style="cursor:help;padding:2px 6px;background:var(--accbg);border:1px solid var(--acc);border-radius:4px;font-size:10px;" onclick="showBatterySaverHelp()" title="Click for help">?</span>
          </div>

          <p style="font-size:11px;color:var(--mut);margin-bottom:12px;">
            Reduces power consumption by stopping WiFi/BLE scanning, lowering CPU frequency, and sending only periodic heartbeats. WiFi AP and web UI remain active. Mesh UART remains active for receiving commands.
          </p>

          <div style="margin-bottom:16px;">
            <label style="font-size:11px;font-weight:bold;margin-bottom:4px;display:block;">Heartbeat Interval</label>
            <label style="font-size:10px;color:var(--mut);margin-bottom:6px;display:block;">How often to send status heartbeats while in battery saver mode</label>
            <select id="batterySaverInterval">
              <option value="1">1 minute</option>
              <option value="2">2 minutes</option>
              <option value="5" selected>5 minutes</option>
              <option value="10">10 minutes</option>
              <option value="15">15 minutes</option>
              <option value="30">30 minutes</option>
            </select>
          </div>

          <div style="display:flex;gap:8px;">
            <button class="btn primary" type="button" onclick="enableBatterySaver()" style="flex:1;">Enable Battery Saver</button>
            <button class="btn alt" type="button" onclick="disableBatterySaver()" style="flex:1;">Disable</button>
          </div>
          <div id="batterySaverStatus" style="margin-top:8px;padding:6px;border-radius:4px;font-size:11px;text-align:center;background:rgba(0,0,0,0.2);">INACTIVE</div>
        </div>
      </div>

      </div>

      <div class="page-tab" id="page-data">
      <div class="card">
        <h3>Data Explorer</h3>
        <div class="data-header">
          <select id="dataSet" onchange="loadDataSet()">
            <option value="probedb">Probe Devices</option>
            <option value="probes">Probe Events</option>
            <option value="deauth">Deauth Attacks</option>
            <option value="drones">Drone Detections</option>
            <option value="vibrations">Vibration Events</option>
            <option value="baseline">Baseline Stats</option>
            <option value="syslog">System Log</option>
            <option value="incidents">Sentinel Incidents (all sessions)</option>
          </select>
          <input type="text" id="dataSearch" placeholder="Search..." oninput="onDataSearch()">
          <button class="btn alt" onclick="loadDataSet()" style="padding:8px 14px;font-size:12px;" title="Refresh">Refresh</button>
          <a class="btn alt" id="dataExport" download style="padding:8px 14px;font-size:12px;">Export</a>
          <button class="btn danger" id="dataClear" onclick="clearDataSet()" style="padding:8px 14px;font-size:12px;">Clear</button>
        </div>
        <div id="dataArea" style="overflow-x:auto;">
          <div class="data-empty">Select a dataset to view.</div>
        </div>
        <div class="data-pager" id="dataPager" style="display:none;">
          <button class="btn alt" onclick="dataPagePrev()" id="dataPrevBtn">Prev</button>
          <span id="dataPageInfo">--</span>
          <button class="btn alt" onclick="dataPageNext()" id="dataNextBtn">Next</button>
        </div>
      </div>
      </div>

      <!-- ===== DETECT TAB ===== -->
      <div class="page-tab" id="page-detect">
        <style>
          #page-detect .sev{display:inline-block;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;margin-right:6px;vertical-align:middle}
          #page-detect .sev.crit{background:#7f1d1d;color:#fff}
          #page-detect .sev.high{background:#ea580c;color:#fff}
          #page-detect .sev.med{background:#ca8a04;color:#fff}
          #page-detect .sev.info{background:#334155;color:#cbd5e1}
          #page-detect .card.hidden{display:none}
          #page-detect details>summary{cursor:pointer;font-weight:bold;color:var(--acc);margin-bottom:8px;list-style:none}
          #page-detect details>summary::-webkit-details-marker{display:none}
          #page-detect details>summary>span:first-child{display:inline-block;width:10px;transition:transform .15s}
          #page-detect details[open]>summary>span:first-child{transform:rotate(90deg)}
          #page-detect .det-row{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:12px;border-bottom:1px solid var(--bord)}
          #page-detect .det-row:last-child{border-bottom:0}
          #page-detect .det-row .name{flex:1;color:var(--txt)}
          #page-detect .det-row label{display:inline-flex;align-items:center;gap:5px;font-size:11px;color:var(--mut);margin:0;cursor:pointer}
          #page-detect .det-row input[type=checkbox]{margin:0;cursor:pointer}
          #page-detect .num{font-family:monospace;color:var(--acc);font-weight:700}
          #page-detect .log-pre{max-height:240px;overflow:auto;font-size:11px;background:var(--surf2,rgba(0,0,0,.15));color:var(--txt);padding:8px;border:1px solid var(--bord);border-radius:4px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
          #page-detect input[type=number],#page-detect input[type=text]{padding:4px 8px;font-size:12px}
          #det-filter{flex:1;min-width:180px;max-width:400px}
          #det-banner{display:none;background:linear-gradient(90deg,rgba(139,92,246,.20),rgba(168,85,247,.10));border:1px solid rgba(139,92,246,.45);border-radius:6px;padding:8px 10px;margin-bottom:10px}
          #det-banner.show{display:block}
          #det-banner .bn-row{display:flex;gap:8px;align-items:center;font-size:12px;padding:3px 0;cursor:pointer}
          #det-banner .bn-row:hover{background:rgba(255,255,255,0.04)}
          #det-banner .bn-when{color:var(--mut);font-size:10px;min-width:60px}
          #det-banner .bn-msg{flex:1;color:var(--txt)}
          .det-chips{display:flex;gap:6px;flex-wrap:wrap}
          .det-chip{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;user-select:none;text-transform:uppercase;letter-spacing:.3px}
          .det-chip.all{background:var(--accbg);color:var(--mut);border-color:var(--bord)}
          .det-chip.crit{background:rgba(239,68,68,.12);color:#ef4444;border-color:rgba(239,68,68,.45)}
          .det-chip.high{background:rgba(249,115,22,.12);color:#f97316;border-color:rgba(249,115,22,.45)}
          .det-chip.med{background:rgba(234,179,8,.14);color:#ca8a04;border-color:rgba(234,179,8,.45)}
          .det-chip.info{background:rgba(14,165,233,.12);color:#0ea5e9;border-color:rgba(14,165,233,.45)}
          .det-chip.firing{box-shadow:0 0 0 2px rgba(255,255,255,.15) inset}
          .det-chip.off{opacity:.35}
          #page-detect table.dt{width:100%;border-collapse:collapse;font-size:12.5px;margin:8px 0}
          #page-detect table.dt th{text-align:left;padding:8px 10px;color:var(--mut);font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--bord);cursor:pointer;user-select:none;white-space:nowrap}
          #page-detect table.dt th:hover{color:var(--acc)}
          #page-detect table.dt td{padding:8px 10px;border-bottom:1px solid var(--bord);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px}
          #page-detect table.dt tr:hover td{background:var(--accbg)}
          #page-detect table.dt .empty{color:var(--mut);font-style:italic;text-align:center;padding:18px}
          .det-quick{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:4px}
          .det-quick button{padding:2px 7px;font-size:11px;min-height:0;line-height:1.4}
          #det-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:12px;align-items:start}
          #det-grid>.card{margin:0}
          #det-grid .log-pre{max-height:180px}
          @media (max-width:720px){#det-grid{grid-template-columns:1fr}}
        </style>

        <div style="margin-bottom:12px;padding:14px 16px;background:linear-gradient(135deg,rgba(139,92,246,.18),rgba(168,85,247,.08));border:1px solid var(--bord);border-radius:10px;">
          <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;">
            <h2 style="margin:0;font-size:20px;letter-spacing:-0.01em;color:var(--txt);">Sentinel</h2>
            <span style="font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.3px;font-weight:600;">Counterintel Engine</span>
          </div>
          <div style="font-size:11px;color:var(--mut);margin-top:6px;line-height:1.5;">
            Passive WiFi monitoring that flags attacker-tool activity.
          </div>
        </div>

        <div id="det-banner"><div style="font-size:10px;color:#fca5a5;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px">ACTIVE ALERTS</div><div id="det-banner-body"></div></div>

        <div id="det-tabs" style="display:flex;gap:2px;margin-bottom:12px;border-bottom:1px solid var(--bord);">
          <button data-dtab="live" class="dtab active" onclick="detSetTab('live')">Live</button>
          <button data-dtab="detectors" class="dtab" onclick="detSetTab('detectors')">Detectors</button>
          <button data-dtab="analysis" class="dtab" onclick="detSetTab('analysis')">Analysis</button>
        </div>
        <style>
          #det-tabs button.dtab{background:transparent;color:var(--mut);border:none;border-bottom:2px solid transparent;padding:8px 14px;font-size:13px;cursor:pointer;font-weight:500;}
          #det-tabs button.dtab:hover{color:var(--txt);background:rgba(255,255,255,.03);}
          #det-tabs button.dtab.active{color:var(--txt);border-bottom-color:#ea580c;}
          .dtab-hidden{display:none !important;}
          .det-empty-hidden{display:none !important;}
          .drow-head,.drow{display:grid;grid-template-columns:10px 1fr 48px 52px 44px;gap:12px;align-items:center;}
          .drow-head{padding:2px 12px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);border-bottom:1px solid var(--bord);}
          .drow-head .rh-r{text-align:right;}
          .drow{padding:10px 12px;border-radius:8px;transition:background .15s;}
          .drow+.drow{margin-top:2px;}
          .drow:hover{background:var(--accbg);}
          .drow-dot{width:8px;height:8px;border-radius:50%;background:var(--mut);opacity:.35;}
          .drow.on .drow-dot{background:var(--succ);opacity:.9;}
          .drow.fire .drow-dot{background:var(--dang);opacity:1;box-shadow:0 0 8px var(--dang);}
          .drow-name{font-size:14px;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
          .drow:not(.on) .drow-name{color:var(--mut);}
          .drow-hits{font-size:13px;font-weight:700;color:var(--mut);text-align:right;}
          .drow-hits.hot{color:var(--dang);}
          .drow-last{font-size:12px;color:var(--mut);text-align:right;}
          .drow-ctrl{justify-self:end;}
          .don-pill{font-size:9px;font-weight:700;letter-spacing:.05em;padding:3px 7px;border-radius:10px;background:var(--accbg);color:var(--succ);border:1px solid var(--bord);}
          .dsw{position:relative;display:inline-block;width:36px;height:20px;cursor:pointer;}
          .dsw input{opacity:0;width:0;height:0;position:absolute;margin:0;}
          .dsw-s{position:absolute;inset:0;background:rgba(120,128,160,.45);border:1px solid var(--bord);border-radius:20px;transition:.2s;}
          .dsw-s:before{content:"";position:absolute;height:14px;width:14px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 2px rgba(0,0,0,.4);}
          .dsw input:checked+.dsw-s{background:var(--succ);}
          .dsw input:checked+.dsw-s:before{transform:translateX(16px);}
          .sa-chip{cursor:pointer;font-size:11px;font-weight:600;padding:4px 10px;border-radius:999px;border:1px solid transparent;transition:all .15s;white-space:nowrap;}
          .sa-chip:hover{filter:brightness(1.2);}
          .sa-wrap{max-height:62vh;overflow:auto;border:1px solid var(--bord);border-radius:10px;}
          .sa-tbl{width:100%;border-collapse:collapse;font-size:13px;}
          .sa-tbl th{position:sticky;top:0;z-index:1;text-align:left;padding:9px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);background:var(--surf);backdrop-filter:blur(8px);border-bottom:1px solid var(--bord);}
          .sa-tbl td{padding:9px 12px;border-bottom:1px solid var(--bord);vertical-align:middle;}
          .sa-tbl tr:last-child td{border-bottom:none;}
          .sa-tbl tbody tr:hover{background:var(--accbg);}
          .sa-pill{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:6px;}
          .sa-crit{background:rgba(244,63,94,.16);color:#fb7185;}
          .sa-high{background:rgba(249,115,22,.16);color:#fb923c;}
          .sa-med{background:rgba(234,179,8,.15);color:#facc15;}
          .sa-info{background:rgba(56,189,248,.14);color:#38bdf8;}
          .sa-type{font-weight:600;color:var(--txt);}
          .sa-mac{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut);}
          .sa-detail{font-family:ui-monospace,monospace;font-size:12px;color:var(--txt);opacity:.8;}
          .sa-when{font-size:12px;color:var(--mut);white-space:nowrap;}
          .sa-node{font-size:10px;color:var(--mut);border:1px solid var(--bord);border-radius:5px;padding:1px 5px;}
          .dpill{display:inline-block;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;letter-spacing:.4px;text-transform:uppercase;margin-left:6px;vertical-align:middle;}
          .dpill.verify{background:rgba(34,197,94,.18);color:#86efac;border:1px solid #16a34a;}
          .dpill.unver{background:rgba(234,179,8,.15);color:#fde047;border:1px solid #ca8a04;}
          .dpill.off{background:rgba(156,163,175,.12);color:#9ca3af;border:1px solid #4b5563;}
          .dpill.fire{background:rgba(239,68,68,.2);color:#fca5a5;border:1px solid #dc2626;animation:dpulse 1.2s ease-in-out infinite;}
          @keyframes dpulse{0%,100%{opacity:1}50%{opacity:.45}}
        </style>

        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detOverviewCard')">
            <h3><span class="sev info">overview</span>Detection Overview</h3>
            <span class="collapse-icon open" id="detOverviewCardIcon">▶</span>
          </div>
          <div class="card-body" id="detOverviewCardBody">
            <div class="stat-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(clamp(96px,12vw,128px),1fr));gap:8px;margin-bottom:10px;">
              <div class="stat" data-cfg="always"><div class="stat-label">Deauth Flood</div><div class="stat-value" id="d-dauth">0</div></div>
              <div class="stat" data-cfg="pmkid"><div class="stat-label">PMKID</div><div class="stat-value" id="d-pmkid">0</div></div>
              <div class="stat" data-cfg="eviltwin"><div class="stat-label">Evil-Twin</div><div class="stat-value" id="d-et">0</div></div>
              <div class="stat" data-cfg="ssid_confusion"><div class="stat-label">SSID Conf</div><div class="stat-value" id="d-sc">0</div></div>
              <div class="stat" data-cfg="sae"><div class="stat-label">SAE DoS</div><div class="stat-value" id="d-sae">0</div></div>
              <div class="stat" data-cfg="owe"><div class="stat-label">OWE Abuse</div><div class="stat-value" id="d-owe">0</div></div>
              <div class="stat" data-cfg="frag"><div class="stat-label">FragAttacks</div><div class="stat-value" id="d-frag">0</div></div>
              <div class="stat" data-cfg="pmkid,probe_flood,hshk"><div class="stat-label">Recon</div><div class="stat-value" id="d-rec">0</div></div>
              <div class="stat" data-cfg="attacker_trilat"><div class="stat-label">Hunts</div><div class="stat-value" id="d-ah-n">0</div></div>
              <div class="stat" data-cfg="hshk"><div class="stat-label">KRACK</div><div class="stat-value" id="d-hs-krack">0</div></div>
              <div class="stat" data-cfg="karma"><div class="stat-label">Karma</div><div class="stat-value" id="d-karma">0</div></div>
              <div class="stat" data-cfg="always" title="mdk4 auth-DoS: open-system Auth flood from many spoofed MACs"><div class="stat-label">Auth-DoS</div><div class="stat-value" id="d-authflood">0</div></div>
              <div class="stat" data-cfg="eviltwin"><div class="stat-label">Beacon Flood</div><div class="stat-value" id="d-beaconflood">0</div></div>
              <div class="stat" data-cfg="assoc_sleep"><div class="stat-label">Assoc Sleep</div><div class="stat-value" id="d-asl">0</div></div>
              <div class="stat" data-cfg="probe_flood"><div class="stat-label">Probe Flood</div><div class="stat-value" id="d-pfl">0</div></div>
              <div class="stat" data-cfg="tsf"><div class="stat-label">TSF / Twin</div><div class="stat-value" id="d-tsf">0</div></div>
              <div class="stat" data-cfg="jam"><div class="stat-label">WiFi Jam</div><div class="stat-value" id="d-jam">0</div></div>
              <div class="stat" data-cfg="mesh_guard"><div class="stat-label">Mesh Guard</div><div class="stat-value" id="d-mgd">0</div></div>
              <div class="stat" data-cfg="pwna"><div class="stat-label">Pwnagotchi</div><div class="stat-value" id="d-pwna">0</div></div>
              <div class="stat" data-cfg="rid_spoof"><div class="stat-label">RID Spoof</div><div class="stat-value" id="d-rid-ov">0</div></div>
            </div>
            <div style="font-size:11px;color:var(--mut);margin-bottom:8px;">
              <span class="lbl">Heap:</span><span id="d-heap" class="num">--</span>
              <span class="lbl" style="margin-left:10px;">Drops:</span><span id="d-drops" class="num">--</span>
              <span class="lbl" style="margin-left:10px;">Mesh-gated:</span><span id="d-mgated" class="num">--</span>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <button class="btn alt" onclick="detectClearAll()">Clear All State</button>
            </div>
          </div>
        </div>

        <div class="card" data-key="apclients">
          <div class="card-header" onclick="toggleCollapse('apClientsCard')">
            <h3><span class="sev" style="background:#14532d;color:#bbf7d0;">clients</span>AP Clients <span style="font-size:11px;color:var(--mut);">(associated with this AP)</span></h3>
            <span class="collapse-icon open" id="apClientsCardIcon">▶</span>
          </div>
          <div class="card-body" id="apClientsCardBody">
            <div id="apClientsArea" style="overflow-x:auto;"><div style="color:var(--mut);font-size:12px;">No clients yet.</div></div>
          </div>
        </div>

        <div class="card" data-key="meshcmd">
          <div class="card-header" onclick="toggleCollapse('meshCmdCard')">
            <h3><span class="sev" style="background:#1e3a5f;color:#bfdbfe;">audit</span>Mesh Commands <span style="font-size:11px;color:var(--mut);">(radio id &rarr; command)</span></h3>
            <span class="collapse-icon open" id="meshCmdCardIcon">&#9654;</span>
          </div>
          <div class="card-body" id="meshCmdCardBody">
            <div id="meshCmdArea" style="overflow-x:auto;"><div style="color:var(--mut);font-size:12px;">No commands logged.</div></div>
          </div>
        </div>

        <div class="card" data-key="dctl">
          <div class="card-header" onclick="toggleCollapse('detCtlCard')">
            <h3><span class="sev info">control</span>Sentinel Control</h3>
            <span class="collapse-icon open" id="detCtlCardIcon">▶</span>
          </div>
          <div class="card-body" id="detCtlCardBody">
            <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap;">
              <span style="font-size:12px;">Sentinel:</span>
              <span id="sentStatus2" style="font-weight:600;color:#888;font-size:13px;">--</span>
              <button id="sentToggleBtn" class="btn primary" onclick="sentinelToggleHdr()">Start</button>
              <span style="font-size:11px;color:var(--mut);margin-left:8px;">Radio:</span>
              <div style="display:flex;gap:0;border:1px solid var(--bord);border-radius:6px;overflow:hidden;">
                <button id="dos-mode-defend" class="btn" style="border-radius:0;margin:0;" onclick="detScanMode(false)">Defend this AP</button>
                <button id="dos-mode-scan" class="btn alt" style="border-radius:0;margin:0;" onclick="detScanMode(true)">Scan all channels</button>
              </div>
            </div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
              <label class="dsw"><input type="checkbox" id="sentBootChk" onchange="sentinelSetBoot(this.checked)"><span class="dsw-s"></span></label>
              <span style="font-size:12px;color:var(--mut);">Start Sentinel on boot (persists across reboot)</span>
            </div>
            <div id="dos-mode-desc" style="font-size:11px;color:var(--mut);margin:-4px 0 10px;"></div>
            <div id="dctl-quick" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:6px;margin-bottom:10px;"></div>
            <p style="font-size:11px;color:var(--mut);margin:2px 0 4px;">Toggle a group:</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:6px;margin-bottom:8px;">
              <button id="grpchip-dos" class="btn alt" onclick="detGroupToggle('dos')">DoS</button>
              <button id="grpchip-rogue_ap" class="btn alt" onclick="detGroupToggle('rogue_ap')">Rogue AP</button>
              <button id="grpchip-recon" class="btn alt" onclick="detGroupToggle('recon')">Recon</button>
              <button id="grpchip-physical" class="btn alt" onclick="detGroupToggle('physical')">Physical</button>
              <button id="grpchip-mesh" class="btn alt" onclick="detGroupToggle('mesh')">Mesh</button>
              <!-- BLE attack group disabled per user 2026-05-23 (BLE scan path unreliable on this build) -->
              <!-- <button id="grpchip-ble" class="btn alt" onclick="detGroupToggle('ble')">BLE</button> -->
            </div>
            <div class="det-quick">
              <button class="btn alt" onclick="detPreset('all-on')">All On</button>
              <button class="btn alt" onclick="detPreset('all-off')">All Off</button>
              <button class="btn alt" onclick="detPreset('quiet')">Quiet</button>
            </div>
          </div>
        </div>

        <div style="margin:4px 0 10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;" data-dtab-target="detectors">
          <input id="det-filter" placeholder="Filter (e.g. airtag, karma, frag)" oninput="detApplyFilters()" style="max-width:240px;">
          <div class="det-chips" id="det-chips">
            <span class="det-chip all" data-sev="all">All</span>
            <span class="det-chip crit" data-sev="crit">Crit</span>
            <span class="det-chip high" data-sev="high">High</span>
            <span class="det-chip med" data-sev="med">Med</span>
            <span class="det-chip info" data-sev="info">Info</span>
            <span class="det-chip" data-sev="firing" style="background:rgba(34,197,94,.14);color:#16a34a;border:1px solid rgba(34,197,94,.45);">Firing</span>
          </div>
        </div>

        <div class="card" data-key="dos">
          <div class="card-header" onclick="toggleCollapse('detDosCard')">
            <h3><span class="sev high">dos</span>DoS Defense</h3>
            <span class="collapse-icon open" id="detDosCardIcon">▶</span>
          </div>
          <div class="card-body" id="detDosCardBody">
            <div id="dos-rows" style="font-size:12px;"></div>
          </div>
        </div>

        <div class="card" data-key="rogue">
          <div class="card-header" onclick="toggleCollapse('detRogueCard')">
            <h3><span class="sev high">rogue</span>Rogue AP</h3>
            <span class="collapse-icon open" id="detRogueCardIcon">▶</span>
          </div>
          <div class="card-body" id="detRogueCardBody">
            <div id="rogue-rows"></div>
          </div>
        </div>

        <div class="card" data-key="recongrp">
          <div class="card-header" onclick="toggleCollapse('detReconGrpCard')">
            <h3><span class="sev high">recon</span>Recon / Harvest</h3>
            <span class="collapse-icon open" id="detReconGrpCardIcon">▶</span>
          </div>
          <div class="card-body" id="detReconGrpCardBody">
            <div id="recon-rows"></div>
          </div>
        </div>

        <div class="card" data-key="physical">
          <div class="card-header" onclick="toggleCollapse('detPhysCard')">
            <h3><span class="sev info">phys</span>Physical Layer</h3>
            <span class="collapse-icon open" id="detPhysCardIcon">▶</span>
          </div>
          <div class="card-body" id="detPhysCardBody">
            <div id="physical-rows"></div>
          </div>
        </div>

        <div class="card" data-key="mesh">
          <div class="card-header" onclick="toggleCollapse('detMeshGrpCard')">
            <h3><span class="sev info">mesh</span>Mesh Disruption</h3>
            <span class="collapse-icon open" id="detMeshGrpCardIcon">▶</span>
          </div>
          <div class="card-body" id="detMeshGrpCardBody">
            <div id="mesh-rows"></div>
          </div>
        </div>

        <!-- BLE attack group card disabled per user 2026-05-23 (BLE scan path unreliable on this build)
        <div class="card" data-key="ble">
          <div class="card-header" onclick="toggleCollapse('detBleGrpCard')">
            <h3><span class="sev info">ble</span>BLE</h3>
            <span class="collapse-icon open" id="detBleGrpCardIcon">&#9654;</span>
          </div>
          <div class="card-body" id="detBleGrpCardBody">
            <div style="display:flex;gap:6px;margin-bottom:8px;">
              <button class="btn alt" onclick="detGroup('ble',true)">All On</button>
              <button class="btn alt" onclick="detGroup('ble',false)">All Off</button>
            </div>
            <div id="ble-rows"></div>
          </div>
        </div>
        -->
        <div id="ble-rows" style="display:none;"></div>

        <div class="card" data-key="meshcfg">
          <div class="card-header" onclick="toggleCollapse('detConfigCard')">
            <h3><span class="sev info">config</span>Mesh &amp; Thresholds</h3>
            <span class="collapse-icon" id="detConfigCardIcon">▶</span>
          </div>
          <div class="card-body" id="detConfigCardBody">
            <p style="font-size:11px;color:var(--mut);margin:0 0 6px;">Detector on/off lives in the group cards (Detectors tab). Here: mesh broadcast + thresholds.</p>
            <div class="det-quick" style="margin-bottom:6px;">
              <button class="btn alt" onclick="detPreset('mesh-all')">Mesh All On</button>
              <button class="btn alt" onclick="detPreset('mesh-silent')">Mesh Silent</button>
            </div>
            <details open>
              <summary><span>▶</span> Mesh Broadcast (forward detections to peers)</summary>
              <div id="cfg-mesh"></div>
            </details>
            <details>
              <summary><span>▶</span> Thresholds &amp; Timing</summary>
              <div id="cfg-thresh" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px;"></div>
              <button class="btn primary" onclick="detSaveThresh()" style="margin-top:8px;">Save Thresholds</button>
            </details>
          </div>
        </div>

        <div class="card">
          <div class="card-header" onclick="toggleCollapse('detMeshCard')">
            <h3><span class="sev info">mesh</span>Mesh Defense</h3>
            <span class="collapse-icon open" id="detMeshCardIcon">▶</span>
          </div>
          <div class="card-body" id="detMeshCardBody">
            <div style="font-size:12px;line-height:1.7;">
              <div><span class="lbl">PPS Lock:</span><span id="d-pps" class="num">--</span></div>
              <div><span class="lbl">Bloom Local:</span><span id="d-bl" class="num">--</span></div>
              <div><span class="lbl">Bloom Neighbor:</span><span id="d-bn" class="num">--</span></div>
              <div><span class="lbl">Quorum Candidates:</span><span id="d-qc" class="num">0</span></div>
            </div>
            <details style="margin-top:10px;">
              <summary><span>▶</span> Quorum Status</summary>
              <pre id="d-quorum" class="log-pre">--</pre>
            </details>
            <details style="margin-top:6px;">
              <summary><span>▶</span> Channel Partition</summary>
              <button class="btn alt" onclick="detectAssignChannels()" style="margin-bottom:6px;">Reassign</button>
              <pre id="d-chan" class="log-pre">--</pre>
            </details>
          </div>
        </div>

        <div id="det-grid">
        <div class="card" data-key="analysis">
          <h3>Sentinel Analysis <span style="font-size:11px;color:var(--mut);">(all sessions)</span></h3>
          <div class="data-header">
            <select id="saType" onchange="loadSentinelAnalysis()"><option value="ALL">All types</option></select>
            <input type="text" id="saSearch" placeholder="Search..." oninput="loadSentinelAnalysis()">
            <button class="btn alt" onclick="refreshSentinelAnalysis()" style="padding:8px 14px;font-size:12px;">Refresh</button>
            <a class="btn alt" href="/api/incidents.jsonl" download style="padding:8px 14px;font-size:12px;">Export</a>
            <button class="btn danger" onclick="clearSentinelAnalysis()" style="padding:8px 14px;font-size:12px;">Clear</button>
          </div>
          <div id="saArea" style="overflow-x:auto;"><div class="data-empty">Open to load sentinel incidents.</div></div>
        </div>

        <div class="card" data-key="events" data-sev="high">
          <div class="card-header" onclick="toggleCollapse('detEventsCard')">
            <h3><span class="sev high">high</span>Incidents (Session)</h3>
            <span class="collapse-icon" id="detEventsCardIcon">▶</span>
          </div>
          <div class="card-body collapsed" id="detEventsCardBody">
            <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center;">
              <label style="font-size:12px;color:var(--mut);margin:0;">Filter:</label>
              <select id="incFilter" style="width:auto;padding:6px 10px;font-size:12px;">
                <option value="">ALL</option>
                <option>DEAUTH_FORGE</option>
                <option>DEAUTH_FLOOD</option>
                <option>EVILTWIN</option>
                <option>KARMA_CAND</option>
                <option>KARMA_CONFIRMED</option>
                <option>BEACON_FORGE</option>
                <option>PMKID_HARVEST</option>
                <option>PMKID_FORGE</option>
                <option>EAPOL_BAIT</option>
                <option>PROBE_FLOOD</option>
                <option>ASSOC_SLEEP</option>
                <option>SAE_DOS</option>
                <option>OWE_ABUSE</option>
                <option>FRAG</option>
                <option>KRACK</option>
                <option>PWNAGOTCHI</option>
                <option>ATTACKER_HUNT</option>
                <option>RECON</option>
              </select>
              <label style="font-size:12px;color:var(--mut);margin:0;">Source:</label>
              <select id="incSrc" style="width:auto;padding:6px 10px;font-size:12px;">
                <option value="">ALL</option>
                <option value="local">Local only</option>
                <option value="peer">Peers only</option>
              </select>
              <button class="btn alt" onclick="loadIncidents()" style="padding:6px 12px;font-size:12px;">Refresh</button>
              <button class="btn alt" onclick="downloadIncidents()" style="padding:6px 12px;font-size:12px;">Download .jsonl</button>
              <button class="btn danger" onclick="clearIncidents()" style="padding:6px 12px;font-size:12px;">Clear All</button>
              <span id="incCount" style="font-size:12px;color:var(--mut);margin-left:auto;">--</span>
            </div>
            <div class="sa-wrap" style="max-height:380px;">
              <table class="sa-tbl" id="incTable">
                <thead>
                  <tr>
                    <th style="width:90px;">Time</th>
                    <th style="width:54px;">Node</th>
                    <th style="width:64px;">Src</th>
                    <th style="width:170px;">Type</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody id="incBody"><tr><td colspan="5" style="padding:12px;color:var(--mut);">Loading…</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
        </div><!-- /det-grid -->
      </div>
      <!-- ===== /DETECT TAB ===== -->

      <div align="center" class="footer">v1.0.1 Beta | Node: <span id="footerNodeId">--</span></div>
    
      <script>
      let tickRunning = false;
      let selectedMode = '0';
      let baselineUpdateInterval = null;
      let lastScanningState = false;
      let lastResultsText = '';
      let meshEnabled = true;
      let vibrationEnabled = true;
      let hbEnabled = false;
      let privacyMode = localStorage.getItem('privacyMode') === '1';
      let lastScanStartTime = 0;
      let radioBusy = false;
      let radioBusyTask = '';
      let prevUniqueDevices = 0;


      function isRadioBusy() {
        if (radioBusy) {
          toast('Radio busy — ' + (radioBusyTask || 'scan') + ' in progress. Stop it first.', 'warning');
          return true;
        }
        return false;
      }

      function stopScan(e) {
        if (e) e.preventDefault();
        lastScanStartTime = 0;
        radioBusy = false;
        radioBusyTask = '';
        if (typeof setScanStatus === 'function') setScanStatus('Idle', 'idle');
        const b = document.getElementById('stopAllBtn');
        if (b) b.style.display = 'none';
        fetch('/stop').then(r => r.text()).then(t => toast(t || 'Scan stopped'))
          .catch(err => toast('Stop failed: ' + err, 'error'));
        setTimeout(() => { if (typeof tick === 'function') tick(); }, 600);
        return false;
      }

      function switchPage(pageName) {
        if (document.activeElement) document.activeElement.blur();
        document.querySelectorAll('.page-tab-btn').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.page-tab').forEach(function(p) { p.classList.remove('active'); });
        var btn = document.querySelector('.page-tab-btn[onclick*="' + pageName + '"]');
        if (btn) btn.classList.add('active');
        var pg = document.getElementById('page-' + pageName);
        if (pg) pg.classList.add('active');
        window.scrollTo(0, 0);
        if (pageName === 'data' && typeof loadDataSet === 'function') loadDataSet();
        if (pageName === 'detect') {
          if (typeof sentinelRefresh === 'function') sentinelRefresh();
          if (typeof detAllTicks === 'function') detAllTicks();
          if (typeof detRenderBanner === 'function') detRenderBanner();
          if (typeof loadIncidents === 'function') loadIncidents();
        }
        if (pageName === 'system' && typeof updateBatterySaverStatus === 'function') updateBatterySaverStatus();
      }
      function pageActive(name) {
        var p = document.getElementById('page-' + name);
        return !!(p && p.classList.contains('active'));
      }

      function switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        event.target.classList.add('active');
        document.getElementById(tabName).classList.add('active');
      }

      async function ajaxForm(form, okMsg) {
        const fd = new FormData(form);
        try {
          const r = await fetch(form.action, {
            method: 'POST',
            body: fd
          });
          const t = await r.text();
          if (!r.ok) { toast(t || ('Error ' + r.status), 'warning'); return; }
          toast(okMsg || t);
        } catch (e) {
          toast('Error: ' + e.message);
        }
      }

      async function load() {
        try {
          const [exportResp, resultsResp] = await Promise.all([
            fetch('/export'),
            fetch('/results')
          ]);
          
          const text = await exportResp.text();
          document.getElementById('list').value = text;
          const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          document.getElementById('targetCount').innerText = lines.length + ' targets';
          
          const resultsText = await resultsResp.text();
          document.getElementById('r').innerHTML = parseAndStyleResults(resultsText);
          
          loadNodeId();
          loadRFConfig();
          loadWiFiConfig();
          loadMeshInterval();
          loadDedupTtl();
        } catch (e) { console.error('[CONFIG] settings panel load failed:', e); }
      }

      async function loadNodeId() {
        try {
          const r = await fetch('/node-id');
          const data = await r.json();
          document.getElementById('nodeId').value = data.nodeId;
          document.getElementById('footerNodeId').innerText = data.nodeId;
          window.__nodeId = data.nodeId;
          const dn = document.getElementById('diagNodeId'); if (dn) dn.innerText = data.nodeId;
        } catch (e) {}
      }
      
      function toggleCollapse(cardId) {
        const body = document.getElementById(cardId + 'Body');
        const icon = document.getElementById(cardId + 'Icon');
        
        if (!body) return;
        
        if (body.classList.contains('collapsed')) {
          body.classList.remove('collapsed');
          body.style.maxHeight = body.scrollHeight + 'px';
          if (icon) icon.classList.add('open');
        } else {
          body.style.maxHeight = body.scrollHeight + 'px';
          setTimeout(() => {
            body.classList.add('collapsed');
            body.style.maxHeight = '0';
          }, 10);
          if (icon) icon.classList.remove('open');
        }
      }

      async function loadRFConfig() {
          try {
            const r = await fetch('/rf-config');
            const cfg = await r.json();
            document.getElementById('globalRssiSlider').value = cfg.globalRssiThreshold || -95;
            document.getElementById('globalRssiValue').innerText = (cfg.globalRssiThreshold || -95) + ' dBm';
            document.getElementById('rfPreset').value = cfg.preset;
            document.getElementById('wifiChannelTime').value = cfg.wifiChannelTime;
            document.getElementById('wifiScanInterval').value = cfg.wifiScanInterval;
            document.getElementById('bleScanInterval').value = cfg.bleScanInterval;
            document.getElementById('bleScanDuration').value = cfg.bleScanDuration;
            document.getElementById('wifiChannels').value = cfg.wifiChannels || '1..14';
            
            // If custom not preset
            const customDiv = document.getElementById('customRFSettings');
            if (customDiv) {
              customDiv.style.display = cfg.preset === 3 ? 'block' : 'none';
            }
          } catch(e) {}
      }

      async function updateRFPresetUI() {
        const preset = parseInt(document.getElementById('rfPreset').value);
        const customDiv = document.getElementById('customRFSettings');
        
        if (!customDiv) return;
        
        customDiv.style.display = preset === 3 ? 'block' : 'none';
        
        if (preset <= 2) {
          const fd = new FormData();
          fd.append('preset', preset);
          
          try {
            await fetch('/rf-config', {method: 'POST', body: fd});
            await loadRFConfig();
          } catch(e) {
            console.error('Failed to apply preset:', e);
          }
        }
      }

      async function loadMeshInterval() {
        try {
          const r = await fetch('/mesh-interval');
          const data = await r.json();
          document.getElementById('meshInterval').value = data.interval;
        } catch(e) {
          console.error('[CONFIG] Failed to load mesh interval:', e);
        }
      }

      async function saveMeshInterval() {
        const interval = document.getElementById('meshInterval').value;
        if (interval < 1500 || interval > 30000) {
          toast('Invalid interval: must be 1500-30000ms', 'error');
          return;
        }

        try {
          const r = await fetch('/mesh-interval', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'interval=' + interval
          });
          const data = await r.text();
          toast(data, 'success');
        } catch(e) {
          toast('Failed to save mesh interval', 'error');
        }
      }

      async function loadDedupTtl() {
        try {
          const r = await fetch('/mesh-dedup-ttl');
          const data = await r.json();
          document.getElementById('meshDedupTtl').value = data.ttl;
          const sd = document.getElementById('meshSessionDedup');
          if (sd) sd.checked = !!data.session;
          const info = document.getElementById('dedupCacheInfo');
          if (info) info.innerText = 'Cache: ' + data.count + ' MACs tracked' + (data.ttl == 0 ? ' (dedup DISABLED)' : '');
        } catch(e) {
          console.error('[CONFIG] loadDedupTtl failed:', e);
        }
      }

      async function saveDedupTtl() {
        const ttl = parseInt(document.getElementById('meshDedupTtl').value);
        if (isNaN(ttl) || ttl < 0 || ttl > 3600) {
          toast('Invalid TTL: must be 0-3600 (0=disable)', 'error');
          return;
        }
        try {
          const r = await fetch('/mesh-dedup-ttl', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'ttl=' + ttl
          });
          const data = await r.text();
          toast(data, 'success');
          loadDedupTtl();
        } catch(e) {
          toast('Failed to save dedup TTL', 'error');
        }
      }

      async function clearDedup() {
        try {
          const r = await fetch('/mesh-dedup-clear', { method: 'POST' });
          const data = await r.text();
          toast(data, 'success');
          loadDedupTtl();
        } catch(e) {
          toast('Failed to clear dedup cache', 'error');
        }
      }

      async function saveSessionDedup() {
        const on = document.getElementById('meshSessionDedup').checked ? 1 : 0;
        try {
          const r = await fetch('/mesh-session-dedup', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'on=' + on
          });
          toast(await r.text(), 'success');
          loadDedupTtl();
        } catch(e) {
          toast('Failed to set session dedup', 'error');
        }
      }

      function togglePrivacy() {
        privacyMode = !privacyMode;
        localStorage.setItem('privacyMode', privacyMode ? '1' : '0');
        updatePrivacyBtn();
        const resultsElement = document.getElementById('r');
        if (privacyMode) {
          if (resultsElement && lastResultsText) {
            resultsElement.innerHTML = parseAndStyleResults(lastResultsText);
          }
          applyPrivacyToElement(document.body);
          document.querySelectorAll('textarea').forEach(ta => {
            ta.value = ta.value.replace(/\b([A-F0-9]{2}:){5}[A-F0-9]{2}\b/gi, 'XX:XX:XX:XX:XX:XX');
            ta.value = ta.value.replace(/(?:probes:|AP=|SSID:\s*)~?"([^"]+)"/g, (m, s) => m.replace(s, ssidHash(s)));
          });
        } else {
          if (resultsElement && lastResultsText) {
            resultsElement.innerHTML = parseAndStyleResults(lastResultsText);
          }
          load();
        }
      }

      function updatePrivacyBtn() {
        const btn = document.getElementById('privacyBtn');
        if (!btn) return;
        btn.textContent = 'Privacy';
        btn.classList.remove('danger');
        btn.style.background = '';
        btn.style.borderColor = '';
        btn.style.color = '';
        if (privacyMode) {
          btn.classList.add('primary');
          btn.classList.remove('alt');
        } else {
          btn.classList.add('alt');
          btn.classList.remove('primary');
        }
      }

      async function toggleMesh() {
        meshEnabled = !meshEnabled;
        updateMeshUI();
        try {
          const r = await fetch('/mesh', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + meshEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update mesh status', 'error');
          meshEnabled = !meshEnabled;
          updateMeshUI();
        }
      }
      
      function updateMeshUI() {
        const btn = document.getElementById('meshToggleBtn');
        const controls = document.getElementById('meshControls');
        
        if (!btn) return;
        
        if (meshEnabled) {
          btn.textContent = 'Mesh: Enabled';
          btn.classList.remove('danger');
          btn.classList.add('primary');
          btn.style.background = 'var(--succ)';
          btn.style.borderColor = 'var(--succ)';
          btn.style.color = '#fff';
          if (controls) controls.style.display = 'block';
        } else {
          btn.textContent = 'Mesh: Disabled';
          btn.classList.remove('primary');
          btn.classList.add('danger');
          btn.style.background = '';
          btn.style.borderColor = '';
          btn.style.color = '';
          if (controls) controls.style.display = 'none';
        }
      }
      
      async function toggleVibration() {
        vibrationEnabled = !vibrationEnabled;
        updateVibrationUI();
        try {
          const r = await fetch('/vibration', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + vibrationEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update vibration status', 'error');
          vibrationEnabled = !vibrationEnabled;
          updateVibrationUI();
        }
      }

      function updateVibrationUI() {
        const btn = document.getElementById('vibToggleBtn');
        if (!btn) return;
        if (vibrationEnabled) {
          btn.textContent = 'Alerts: Enabled';
          btn.classList.remove('danger');
          btn.style.background = 'var(--succ)';
          btn.style.borderColor = 'var(--succ)';
          btn.style.color = '#fff';
        } else {
          btn.textContent = 'Alerts: Disabled';
          btn.classList.add('danger');
          btn.style.background = '';
          btn.style.borderColor = '';
          btn.style.color = '';
        }
      }

      function updateHbUI() {
        const cb = document.getElementById('hbEnabledCb');
        if (cb) cb.checked = hbEnabled;
      }

      async function toggleHb() {
        hbEnabled = document.getElementById('hbEnabledCb').checked;
        try {
          const r = await fetch('/mesh-hb', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'enabled=' + hbEnabled
          });
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to update heartbeat', 'error');
          hbEnabled = !hbEnabled;
          updateHbUI();
        }
      }

      async function saveHbInterval() {
        const minutes = parseInt(document.getElementById('hbIntervalInput').value);
        if (isNaN(minutes) || minutes < 1 || minutes > 60) { toast('Interval must be 1–60 min', 'error'); return; }
        try {
          const r = await fetch('/mesh-hb-interval', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'interval=' + minutes
          });
          toast(await r.text(), 'success');
        } catch(e) { toast('Failed to set interval', 'error'); }
      }

      function loadMeshStatus() {
        updateMeshUI();
      }

      async function saveRFConfig() {
        const preset = parseInt(document.getElementById('rfPreset').value);
        const threshold = parseInt(document.getElementById('globalRssiSlider').value);
        const fd = new FormData();
        
        fd.append('globalRssiThreshold', threshold);
        
        if (preset === 3) {
          fd.append('wifiChannelTime', document.getElementById('wifiChannelTime').value);
          fd.append('wifiScanInterval', document.getElementById('wifiScanInterval').value);
          fd.append('bleScanInterval', document.getElementById('bleScanInterval').value);
          fd.append('bleScanDuration', document.getElementById('bleScanDuration').value);
          fd.append('wifiChannels', document.getElementById('wifiChannels').value);
        } else {
          fd.append('preset', preset);
        }
        
        try {
          const r = await fetch('/rf-config', {method: 'POST', body: fd});
          const msg = await r.text();
          toast(msg, 'success');
        } catch(e) {
          toast('Failed to save RF config', 'error');
        }
      }

      async function saveWiFiConfig() {
        const ssid = document.getElementById('apSsid').value.trim();
        const pass = document.getElementById('apPass').value;
        
        if (ssid.length === 0) {
          toast('SSID cannot be empty');
          return;
        }
        
        if (pass.length > 0 && pass.length < 8) {
          toast('Password must be at least 8 characters');
          return;
        }
        
        const fd = new FormData();
        fd.append('ssid', ssid);
        fd.append('pass', pass);
        fd.append('auth', document.getElementById('apAuth').value);

        try {
          const r = await fetch('/wifi-config', {method: 'POST', body: fd});
          const msg = await r.text();
          toast(msg);
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function loadWiFiConfig() {
        try {
          const r = await fetch('/wifi-config');
          const cfg = await r.json();
          document.getElementById('apSsid').value = cfg.ssid;
          document.getElementById('apPass').value = cfg.pass;
          if (cfg.auth !== undefined) document.getElementById('apAuth').value = cfg.auth;
        } catch(e) {}
      }
      
      function toggleCard(cardId) {
        const card = document.getElementById(cardId);
        const toggle = document.getElementById(cardId.replace('Card', 'Toggle'));
        if (card.style.display === 'none') {
          card.style.display = 'block';
          toggle.style.transform = 'rotate(0deg)';
        } else {
          card.style.display = 'none';
          toggle.style.transform = 'rotate(-90deg)';
        }
      }
           
      async function loadBaselineAnomalyConfig() {
        try {
          const r = await fetch('/baseline/config');
          const data = await r.json();
          if (data.rssiThreshold !== undefined) {
            document.getElementById('baselineRssiThreshold').value = data.rssiThreshold;
          }
          if (data.baselineDuration !== undefined) {
            document.getElementById('baselineDuration').value = data.baselineDuration;
          }
          if (data.ramCacheSize !== undefined) {
            document.getElementById('baselineRamSize').value = data.ramCacheSize;
          }
          if (data.sdMaxDevices !== undefined) {
            document.getElementById('baselineSdMax').value = data.sdMaxDevices;
          }
          if (data.absenceThreshold !== undefined) {
            document.getElementById('absenceThreshold').value = data.absenceThreshold;
          }
          if (data.reappearanceWindow !== undefined) {
            document.getElementById('reappearanceWindow').value = data.reappearanceWindow;
          }
          if (data.rssiChangeDelta !== undefined) {
            document.getElementById('rssiChangeDelta').value = data.rssiChangeDelta;
          }
        } catch(error) {
          console.error('Error loading baseline config:', error);
        }
        
        try {
          const r = await fetch('/allowlist-export');
          const t = await r.text();
          document.getElementById('wlist').value = t;
          document.getElementById('allowlistCount').textContent = t.split('\n').filter(x => x.trim()).length + ' entries';
        } catch(error) {
          console.error('Error loading allowlist:', error);
        }
      }

      async function clearOldIdentities() {
        if (!confirm('Clear device identities older than 1 hour?')) return;
        try {
          const response = await fetch('/randomization/clear-old', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'age=3600'
          });
          const data = await response.text();
          toast(data, 'success');
        } catch (error) {
          toast('Error: ' + error, 'error');
        }
      }

      let baselineUpdating = false;
      async function updateBaselineStatus() {
        if (baselineUpdating) return;
        const detectionMode = document.getElementById('detectionMode');
        const statusDiv = document.getElementById('baselineStatus');
        if (!detectionMode || detectionMode.value !== 'baseline') {
          if (statusDiv) statusDiv.style.display = 'none';
          if (baselineUpdateInterval) {
            clearInterval(baselineUpdateInterval);
            baselineUpdateInterval = null;
          }
          return;
        }
        if (statusDiv) statusDiv.style.display = '';
        baselineUpdating = true;
        try {
          const response = await fetch('/baseline/stats');
          const stats = await response.json();
          const statusDiv = document.getElementById('baselineStatus');
          if (!statusDiv) return;
          let statusHTML = '';
          let progressHTML = '';
          if (stats.scanning && !stats.phase1Complete) {
            // Phase 1: Establishing baseline
            const progress = Math.min(100, (stats.elapsedTime / stats.totalDuration) * 100);
            statusHTML = '<div style="color:var(--succ);font-weight:bold;">⬤ Phase 1: Establishing Baseline...</div>';
            progressHTML = '<div style="margin-top:10px;">' + '<div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px;">' + '<span>Progress</span>' + '<span>' + Math.floor(progress) + '%</span>' + '</div>' + '<div style="width:100%;height:6px;background:var(--bord);border-radius:3px;overflow:hidden;">' + '<div style="height:100%;width:' + progress + '%;background:linear-gradient(90deg,var(--succ),var(--acc));transition:width 0.5s;"></div>' + '</div>' + '</div>';
          } else if (stats.scanning && stats.phase1Complete) {
            // Phase 2: Monitoring - add active status indicator
            statusHTML = '<div style="color:var(--acc);font-weight:bold;">⬤ Phase 2: Monitoring for Anomalies</div>';
            // Add elapsed time indicator for Phase 2
            const monitorTime = Math.floor(stats.elapsedTime / 1000);
            const monitorMins = Math.floor(monitorTime / 60);
            const monitorSecs = monitorTime % 60;
            progressHTML = '<div style="margin-top:10px;color:var(--succ);font-size:11px;">' + 'Active monitoring: ' + monitorMins + 'm ' + monitorSecs + 's' + '</div>';
          } else if (stats.established) {
            // Complete
            statusHTML = '<div style="color:var(--succ);">✓ Baseline Complete</div>';
          } else {
            statusHTML = '<div style="color:var(--mut);">No baseline data</div>';
          }
          let statsHTML = '';
          if (stats.scanning) {
            const cur = stats.totalDevices;
            const newBadge = (cur > prevUniqueDevices && prevUniqueDevices > 0) ? ' <span style="color:var(--succ);font-size:10px;font-weight:normal;">(+' + (cur - prevUniqueDevices) + ' new)</span>' : '';
            statsHTML = '<div style="margin-top:12px;padding:10px;background:var(--surf);border:1px solid var(--bord);border-radius:8px;">' + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px;">' + '<div>' + '<div style="color:var(--mut);">WiFi Devices</div>' + '<div style="color:var(--txt);font-size:16px;font-weight:bold;">' + stats.wifiDevices + '</div>' + '<div style="color:var(--mut);font-size:10px;">' + stats.wifiHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">BLE Devices</div>' + '<div style="color:var(--txt);font-size:16px;font-weight:bold;">' + stats.bleDevices + '</div>' + '<div style="color:var(--mut);font-size:10px;">' + stats.bleHits + ' frames</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">Total Devices</div>' + '<div style="color:var(--acc);font-size:16px;font-weight:bold;">' + cur + newBadge + '</div>' + '</div>' + '<div>' + '<div style="color:var(--mut);">Anomalies</div>' + '<div style="color:' + (stats.anomalies > 0 ? 'var(--dang)' : 'var(--txt)') + ';font-size:16px;font-weight:bold;">' + stats.anomalies + '</div>' + '</div>' + '</div>' + '</div>';
            // Also update system overview unique devices
            const el = document.getElementById('uniqueDevices');
            if (el) {
              if (cur > prevUniqueDevices && prevUniqueDevices > 0) {
                el.innerHTML = cur + ' <span style="color:var(--succ);font-size:11px;font-weight:normal;">(+' + (cur - prevUniqueDevices) + ' new)</span>';
                el.style.transition = 'color 0.3s';
                el.style.color = 'var(--succ)';
                setTimeout(() => { el.style.color = ''; }, 2000);
              } else {
                el.innerText = cur;
              }
            }
            prevUniqueDevices = cur;
          }
          statusDiv.innerHTML = statusHTML + progressHTML + statsHTML;

          // Always refresh results while scanning — keeps results in sync with phases card
          if (stats.scanning) {
            try {
              const rr = await fetch('/results');
              const rt = await rr.text();
              // Don't regress to empty/placeholder while scanning
              if (rt && rt.trim() !== '' && !rt.includes('None yet') && !rt.includes('No scan data') && rt !== lastResultsText) {
                lastResultsText = rt;
                const re = document.getElementById('r');
                if (re) {
                  const dkey = sm => sm.textContent.trim().replace(/\s*\([^)]*\)\s*$/, '');
                  const openDetails = new Set();
                  re.querySelectorAll('details[open]').forEach(d => { const sm = d.querySelector('summary'); if (sm) openDetails.add(dkey(sm)); });
                  re.innerHTML = parseAndStyleResults(rt);
                  if (openDetails.size) re.querySelectorAll('details').forEach(d => { const sm = d.querySelector('summary'); if (sm && openDetails.has(dkey(sm))) d.open = true; });
                  if (typeof currentSort !== 'undefined' && currentSort !== 'default' && typeof sortResultsDisplay === 'function') sortResultsDisplay();
                }
              }
            } catch(e) {}
          }

          const startDetectionBtn = document.getElementById('startDetectionBtn');
          const detectionMode = document.getElementById('detectionMode')?.value;
          const cacheBtn = document.getElementById('cacheBtn');
          const clearOldBtn = document.getElementById('clearOldBtn');
          
          if (cacheBtn) cacheBtn.style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
          if (clearOldBtn) clearOldBtn.style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
          
           if (detectionMode === 'baseline' && stats.scanning) {
            startDetectionBtn.textContent = stats.phase1Complete ? 'Stop Monitoring' : 'Stop Baseline';
            startDetectionBtn.classList.remove('primary');
            startDetectionBtn.classList.add('danger');
            startDetectionBtn.type = 'button';
            startDetectionBtn.onclick = async function(e) {
              e.preventDefault();
              try {
                const response = await fetch('/stop');
                const text = await response.text();
                toast(text);
                setTimeout(updateBaselineStatus, 500);
              } catch (error) {
                console.error('Stop error:', error);
              }
            };
          } else if (detectionMode === 'baseline' && !stats.scanning) {
            startDetectionBtn.textContent = 'Start Scan';
            startDetectionBtn.classList.remove('danger');
            startDetectionBtn.classList.add('primary');
            startDetectionBtn.type = 'submit';
            startDetectionBtn.onclick = null;
          }    
          // Polling from scan state
          if (stats.scanning && !baselineUpdateInterval) {
            baselineUpdateInterval = setInterval(updateBaselineStatus, 2000);
          } else if (!stats.scanning && baselineUpdateInterval) {
            clearInterval(baselineUpdateInterval);
            baselineUpdateInterval = null;
            prevUniqueDevices = 0;
          }
        } catch(error) {
          console.error('Status update error:', error);
        } finally {
          baselineUpdating = false;
        }
      }

      // Initial load
      updateBaselineStatus();
      // Poll every 2 seconds when not actively scanning
      setInterval(() => {
        const detectionMode = document.getElementById('detectionMode');
        if (detectionMode && detectionMode.value === 'baseline' && !baselineUpdateInterval) {
          updateBaselineStatus();
        }
      }, 2000);
      
      async function saveBaselineConfig() {
        const rssiThreshold = document.getElementById('baselineRssiThreshold').value;
        const duration = document.getElementById('baselineDuration').value;
        const ramSize = document.getElementById('baselineRamSize').value;
        const sdMax = document.getElementById('baselineSdMax').value;
        
        try {
          const response = await fetch('/baseline/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `rssiThreshold=${rssiThreshold}&baselineDuration=${duration}&ramCacheSize=${ramSize}&sdMaxDevices=${sdMax}`
          });
          const data = await response.text();
          toast('Baseline configuration saved', 'success');
          await updateBaselineStatus();
        } catch (error) {
          toast('Error saving config: ' + error, 'error');
        }
      }
      
      async function resetBaseline() {
        if (!confirm('Are you sure you want to reset the baseline? This will clear all collected data.')) return;
        try {
          const response = await fetch('/baseline/reset', { method: 'POST' });
          const data = await response.text();
          toast(data, 'success');
          await updateBaselineStatus();
        } catch (error) {
          toast('Error resetting baseline: ' + error, 'error');
        }
      }

      function clearResults() {
        if (!confirm('Clear scan results?')) return;
        
        fetch('/clear-results', { method: 'POST' })
          .then(r => r.text())
          .then(() => {
            document.getElementById('r').innerText = 'No scan data yet.';
            toast('Results cleared', 'info');
          })
          .catch(err => {
            console.error('Clear failed:', err);
            toast('Failed to clear results', 'error');
          });
      }
      
      let currentSort = 'default';
      let sortReverse = false;

      function applySorting() {
        currentSort = document.getElementById('sortBy').value;
        sortResultsDisplay();
      }

      function applyPrivacyToElement(el) {
        // Replace MAC addresses in all text nodes
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null, false);
        const textNodes = [];
        while (walker.nextNode()) textNodes.push(walker.currentNode);
        textNodes.forEach(node => {
          node.nodeValue = node.nodeValue.replace(
            /\b([A-F0-9]{2}:){5}[A-F0-9]{2}\b/gi,
            'XX:XX:XX:XX:XX:XX'
          );
        });

        // Replace device names — <strong> whose parent div starts with "Name:"
        el.querySelectorAll('strong').forEach(strong => {
          if (strong.parentElement?.textContent.startsWith('Name:')) {
            strong.textContent = 'REDACTED';
          }
        });

        // Replace GPS coordinates — leaf divs containing only a float with 4+ decimals
        el.querySelectorAll('div').forEach(div => {
          if (div.children.length === 0 &&
              /^-?\d{1,3}\.\d{4,}$/.test(div.textContent.trim())) {
            div.textContent = 'REDACTED';
          }
        });

        // Redact SSIDs — all elements with data-ssid attribute
        el.querySelectorAll('[data-ssid]').forEach(elem => {
          const original = elem.getAttribute('data-ssid');
          const hashed = ssidHash(original);
          const sup = elem.querySelector('sup');
          if (sup) {
            const supText = sup.textContent;
            elem.textContent = '';
            elem.appendChild(document.createTextNode(hashed + ' '));
            const newSup = document.createElement('sup');
            newSup.textContent = supText;
            elem.appendChild(newSup);
          } else {
            elem.textContent = hashed;
          }
          elem.title = 'REDACTED';
        });

        // Redact device names — all elements with data-name attribute
        el.querySelectorAll('[data-name]').forEach(elem => {
          elem.textContent = ssidHash(elem.getAttribute('data-name'));
          elem.title = 'REDACTED';
        });

        // Redact AP responded SSIDs
        el.querySelectorAll('[data-ap-ssid]').forEach(div => {
          const strong = div.querySelector('strong');
          if (strong) strong.textContent = ssidHash(div.getAttribute('data-ap-ssid'));
        });
      }

      function ssidHash(ssid) {
        if (!ssid || ssid.length === 0) return '?';
        let h = 0x811c9dc5;
        for (let i = 0; i < ssid.length; i++) {
          h ^= ssid.charCodeAt(i);
          h = Math.imul(h, 0x01000193);
        }
        return 'net#' + ((h >>> 0) & 0xFFFF).toString(16).padStart(4, '0');
      }

      function toggleSortOrder() {
        sortReverse = !sortReverse;
        sortResultsDisplay();
      }

      function sortResultsDisplay() {
        const resultsElement = document.getElementById('r');
        
        if (currentSort === 'default') {
          return;
        }
        
        const isRandomization = resultsElement.textContent.includes('Randomized Device Tracer');
        const isBaseline = resultsElement.textContent.includes('Baseline') || resultsElement.querySelector('.baseline-marker');
        const isDeauth = resultsElement.textContent.includes('Deauth Attack Detection');
        const isDrone = resultsElement.textContent.includes('Drone Detection');
        const isDeviceScan = resultsElement.textContent.includes('Device Discovery');
        
        let items = [];
        const preservedElements = [];
        
        if (isRandomization) {
          Array.from(resultsElement.children).forEach(child => {
            if (child.tagName === 'DETAILS') {
              const summary = child.querySelector('summary');
              if (!summary) {
                preservedElements.push(child);
                return;
              }
              
              const macElement = summary.querySelector('.res-mac');
              const mac = macElement ? macElement.textContent.trim() : '';
              
              const summaryText = summary.textContent;
              const confidenceMatch = summaryText.match(/(\d+)%/);
              const confidence = confidenceMatch ? parseInt(confidenceMatch[1]) : 0;
              
              const rssiMatch = summaryText.match(/([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : -999;
              
              const detailsContent = child.textContent;
              const sessionsMatch = detailsContent.match(/SESSIONS\s*(\d+)/);
              const sessions = sessionsMatch ? parseInt(sessionsMatch[1]) : 0;
              
              const lastSeenMatch = detailsContent.match(/LAST SEEN\s*(\d+)s/);
              const lastSeen = lastSeenMatch ? parseInt(lastSeenMatch[1]) : 999999;
              
              const trackIdMatch = detailsContent.match(/TRACK ID\s*([A-Z0-9-]+)/);
              const trackId = trackIdMatch ? trackIdMatch[1].trim() : '';
              
              const deviceType = child.getAttribute('data-type') || '';
              
              items.push({
                element: child,
                mac, confidence, rssi, sessions, lastSeen, trackId, deviceType,
                sortKey: currentSort,
                type: 'randomization'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isBaseline) {
          // Sort each device-card group in place within its own parent (anomaly cards and baseline-devices stay separate); MAC tiebreaker keeps order stable across live polls.
          const cards = Array.from(resultsElement.querySelectorAll('.device-card'));
          if (cards.length === 0) return;
          const groups = new Map();
          cards.forEach(c => {
            const p = c.parentElement;
            if (!groups.has(p)) groups.set(p, []);
            groups.get(p).push(c);
          });
          const macOf = el => (el.textContent.match(/([0-9A-F]{2}(?::[0-9A-F]{2}){5})/i) || [])[1] || '';
          const rssiOf = el => { const m = el.textContent.match(/(-?\d+)\s*dBm/); return m ? parseInt(m[1]) : 0; };
          const nameOf = el => { const m = el.textContent.match(/Name:\s*([^\n]+)/); return m ? m[1].trim() : ''; };
          const cmpBaseline = (a, b) => {
            let cmp = 0;
            switch (currentSort) {
              case 'rssi-desc': cmp = rssiOf(b) - rssiOf(a); break;
              case 'rssi-asc': cmp = rssiOf(a) - rssiOf(b); break;
              case 'name-asc': cmp = (nameOf(a) || macOf(a)).localeCompare(nameOf(b) || macOf(b)); break;
              case 'type-asc': cmp = (a.getAttribute('data-type') || '').localeCompare(b.getAttribute('data-type') || ''); break;
              case 'channel-asc': cmp = parseInt(a.getAttribute('data-channel') || '0') - parseInt(b.getAttribute('data-channel') || '0'); break;
              default: cmp = 0;
            }
            if (cmp === 0) cmp = macOf(a).localeCompare(macOf(b));
            return sortReverse ? -cmp : cmp;
          };
          groups.forEach((list, parent) => {
            const marker = document.createComment('s');
            parent.insertBefore(marker, list[0]);
            list.forEach(c => parent.removeChild(c));
            list.sort(cmpBaseline);
            list.forEach(c => parent.insertBefore(c, marker));
            parent.removeChild(marker);
          });
          return;
        } else if (isDeauth) {
          Array.from(resultsElement.children).forEach(child => {
            const hasDeauthBorder = child.classList.contains('res-card');
            if (hasDeauthBorder) {
              const macMatch = child.textContent.match(/([A-F0-9:]+|\[BROADCAST\])/);
              const mac = macMatch ? macMatch[1] : '';
              
              const totalMatch = child.textContent.match(/Total Attacks[\s\S]*?(\d+)/);
              const attacks = totalMatch ? parseInt(totalMatch[1]) : 0;
              
              const rssiMatch = child.textContent.match(/Signal[\s\S]*?([-\d]+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              items.push({
                element: child,
                mac, attacks, rssi,
                sortKey: currentSort,
                type: 'deauth'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isDrone) {
          Array.from(resultsElement.children).forEach(child => {
            const hasDroneBorder = child.classList.contains('res-card');
            if (hasDroneBorder) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const mac = macMatch ? macMatch[1] : '';
              
              const rssiMatch = child.textContent.match(/(-?\d+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              items.push({
                element: child,
                mac, rssi,
                sortKey: currentSort,
                type: 'drone'
              });
            } else {
              preservedElements.push(child);
            }
          });
        } else if (isDeviceScan) {
          Array.from(resultsElement.children).forEach(child => {
            if (child.classList.contains('device-card')) {
              const macMatch = child.textContent.match(/([A-F0-9:]+)/);
              const mac = macMatch ? macMatch[1] : '';
              
              const rssiMatch = child.textContent.match(/(-?\d+)\s*dBm/);
              const rssi = rssiMatch ? parseInt(rssiMatch[1]) : 0;
              
              const nameMatch = child.textContent.match(/Name:\s*([^\n]+)/);
              const name = nameMatch ? nameMatch[1].trim() : '';
              
              const deviceType = child.getAttribute('data-type') || '';
              const channel = parseInt(child.getAttribute('data-channel') || '0', 10);
              const isTarget = child.getAttribute('data-target') === '1';

              items.push({
                element: child,
                mac, rssi, name, deviceType, channel, isTarget,
                sortKey: currentSort,
                type: 'device'
              });
            } else {
              preservedElements.push(child);
            }
          });
        }
        
        if (items.length === 0) {
          return;
        }
        
        items.sort((a, b) => {
          if ((a.isTarget ? 1 : 0) !== (b.isTarget ? 1 : 0)) return a.isTarget ? -1 : 1;
          let cmp = 0;

          switch(currentSort) {
            case 'rssi-desc':
              cmp = b.rssi - a.rssi;
              break;
            case 'rssi-asc':
              cmp = a.rssi - b.rssi;
              break;
            case 'confidence-desc':
              cmp = (b.confidence || 0) - (a.confidence || 0);
              break;
            case 'sessions-desc':
              cmp = (b.sessions || 0) - (a.sessions || 0);
              break;
            case 'lastseen-asc':
              cmp = (a.lastSeen || 0) - (b.lastSeen || 0);
              break;
            case 'name-asc':
              cmp = (a.name || a.mac).localeCompare(b.name || b.mac);
              break;
            case 'type-asc':
              cmp = (a.deviceType || '').localeCompare(b.deviceType || '');
              break;
            case 'channel-asc':
              cmp = (a.channel || 0) - (b.channel || 0);
              break;
            default:
              cmp = 0;
          }
          
          return sortReverse ? -cmp : cmp;
        });
        
        resultsElement.innerHTML = '';
        
        preservedElements.forEach(el => {
          resultsElement.appendChild(el);
        });
        
        items.forEach(item => {
          resultsElement.appendChild(item.element);
        });
      }

      // Override the parseAndStyleResults to reset sort after reload
      const originalParseAndStyleResults = window.parseAndStyleResults;
      window.parseAndStyleResults = function(text) {
        const html = originalParseAndStyleResults.call(this, text);
        if (!privacyMode) return html;
        const temp = document.createElement('div');
        temp.innerHTML = html;
        applyPrivacyToElement(temp);
        return temp.innerHTML;
      };
      
      const scanTaskLabels = {
        scan: 'List Scan', sniffer: 'Device Scan', drone: 'Drone Detect',
        blueteam: 'Blue Team', baseline: 'Baseline', randdetect: 'Rand Detect',
        probedet: 'Probe Detect', triangulate: 'Triangulate'
      };
      let _scanBaseLabel = '', _scanEndTs = 0, _scanForever = false;
      function _fmtCountdown(sec) { sec = Math.max(0, Math.floor(sec)); const m = Math.floor(sec / 60), s = sec % 60; return m + ':' + (s < 10 ? '0' : '') + s; }
      function renderScanStatus() {
        const el = document.getElementById('scanStatus');
        if (!el || !el.classList.contains('active')) return;
        if (_scanForever || !_scanEndTs) { el.innerText = _scanBaseLabel; return; }
        el.innerText = _scanBaseLabel + ' · ' + _fmtCountdown((_scanEndTs - Date.now()) / 1000);
      }
      setInterval(renderScanStatus, 1000);
      function setScanStatus(label, state) {
        const el = document.getElementById('scanStatus');
        if (!el) return;
        _scanBaseLabel = label;
        el.classList.remove('idle', 'active');
        if (state) el.classList.add(state);
        if (state !== 'active') { _scanEndTs = 0; _scanForever = false; }
        el.innerText = label;
        renderScanStatus();
      }
      function updateMeshTxIndicator(diagText) {
        const el = document.getElementById('meshTxStatus');
        if (!el) return;
        const m = diagText.match(/Mesh TX: draining (\d+)\/(\d+)/);
        if (m) {
          el.innerText = 'Mesh TX ' + m[1] + '/' + m[2] + ' (cancel)';
          el.style.display = '';
          el.classList.add('active');
        } else {
          el.style.display = 'none';
          el.classList.remove('active');
        }
      }
      async function cancelMeshDrain() {
        try {
          const r = await fetch('/stop');
          if (r.ok) toast('Mesh TX drain cancelled', 'info');
          else toast('Cancel failed (' + r.status + ')', 'error');
        } catch (e) { toast('Cancel failed: ' + e, 'error'); }
        setTimeout(tick, 200);
      }
      function updateStatusIndicators(diagText) {
        const taskTypeMatch = diagText.match(/Task Type: ([^\n]+)/);
        const taskType = taskTypeMatch ? taskTypeMatch[1].trim() : 'none';
        const isScanning = diagText.includes('Scanning: yes');
        const isTriangulating = diagText.includes('Triangulating: yes');
        const detectionMode = document.getElementById('detectionMode')?.value;

        document.getElementById('cacheBtn').style.display = (detectionMode === 'device-scan') ? 'inline-block' : 'none';
        document.getElementById('clearOldBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';
        document.getElementById('resetRandBtn').style.display = (detectionMode === 'randomization-detection') ? 'inline-block' : 'none';

        if (isScanning || isTriangulating) {
            const label = scanTaskLabels[taskType] || (isTriangulating ? 'Triangulate' : 'Scanning');
            const remMatch = diagText.match(/Scan remaining: (\d+|forever)/);
            if (remMatch && remMatch[1] !== 'forever') { _scanForever = false; _scanEndTs = Date.now() + parseInt(remMatch[1]) * 1000; }
            else { _scanForever = !!remMatch; _scanEndTs = 0; }
            setScanStatus(label, 'active');
            
            const startScanBtn = document.querySelector('#s button');
            if (startScanBtn && taskType === 'scan') {
                startScanBtn.textContent = 'Stop Scanning';
                startScanBtn.classList.remove('primary');
                startScanBtn.classList.add('danger');
                startScanBtn.type = 'button';
                startScanBtn.onclick = function(e) {
                    e.preventDefault();
                    lastScanStartTime = 0;
                    fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                        setTimeout(async () => {
                            const refreshedDiag = await fetch('/diag').then(r => r.text());
                            updateStatusIndicators(refreshedDiag);
                        }, 500);
                    });
                };
            }

            if (taskType === 'triangulate') {
                const triangulateBtn = document.querySelector('#s button');
                if (triangulateBtn) {
                    triangulateBtn.textContent = 'Stop Scan';
                    triangulateBtn.classList.remove('primary');
                    triangulateBtn.classList.add('danger');
                    triangulateBtn.type = 'button';
                    triangulateBtn.onclick = function(e) {
                        e.preventDefault();
                        lastScanStartTime = 0;
                        fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                            setTimeout(async () => {
                                const refreshedDiag = await fetch('/diag').then(r => r.text());
                                updateStatusIndicators(refreshedDiag);
                            }, 500);
                        });
                    };
                }
            }

            if (taskType === 'sniffer' || taskType === 'drone' || taskType === 'randdetect' || taskType === 'blueteam' || taskType === 'probedet') {
                const startDetectionBtn = document.getElementById('startDetectionBtn');
                if (startDetectionBtn) {
                    startDetectionBtn.textContent = 'Stop Scanning';
                    startDetectionBtn.classList.remove('primary');
                    startDetectionBtn.classList.add('danger');
                    startDetectionBtn.type = 'button';
                    startDetectionBtn.onclick = function(e) {
                        e.preventDefault();
                        lastScanStartTime = 0;
                        fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                            setTimeout(async () => {
                                const refreshedDiag = await fetch('/diag').then(r => r.text());
                                updateStatusIndicators(refreshedDiag);
                            }, 500);
                        });
                    };
                }
            }
        } else {
            const isWithinGracePeriod = (Date.now() - lastScanStartTime) < 3000;

            if (!isWithinGracePeriod) {
                setScanStatus('Idle', 'idle');

                const startScanBtn = document.querySelector('#s button');
                if (startScanBtn) {
                    startScanBtn.textContent = 'Start Scan';
                    startScanBtn.classList.remove('danger');
                    startScanBtn.classList.add('primary');
                    startScanBtn.type = 'submit';
                    startScanBtn.onclick = null;
                    startScanBtn.style.background = '';
                }

                const detectionMode = document.getElementById('detectionMode')?.value;
                if (detectionMode !== 'baseline') {
                    const startDetectionBtn = document.getElementById('startDetectionBtn');
                    if (startDetectionBtn) {
                        startDetectionBtn.textContent = 'Start Scan';
                        startDetectionBtn.classList.remove('danger');
                        startDetectionBtn.classList.add('primary');
                        startDetectionBtn.type = 'submit';
                        startDetectionBtn.onclick = null;
                    }
                }
            }
        }

        if (diagText.includes('GPS: Locked')) {
            document.getElementById('gpsStatus').classList.add('active');
            var _gam = diagText.match(/GPS: Locked\s+~([\d.]+)m/);
            document.getElementById('gpsStatus').innerHTML = 'GPS Lock' + (_gam ? ' <span class="gps-acc">~' + _gam[1] + 'm</span>' : '');
        } else {
            document.getElementById('gpsStatus').classList.remove('active');
            document.getElementById('gpsStatus').innerText = 'GPS';
        }
        
      }
        
      function updateModeStatus() {
        // Header mode badge reflects the ACTUAL active radio (Active Radio from /diag),
        // not the planned scan-mode select. No-op kept for existing callers.
      }
      
      function _chipVal(field) {
        const el = document.querySelector('.field-row[data-field="' + field + '"] .chip.active');
        return el ? el.dataset.value : '';
      }
      function _setChipVal(field, value) {
        const row = document.querySelector('.field-row[data-field="' + field + '"]');
        if (!row) return;
        row.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        const target = row.querySelector('.chip[data-value="' + value + '"]');
        if (target) target.classList.add('active');
      }
      function _applyAePreset(preset, setupMs, delayMs, cooldownMs) {
        const chips = document.querySelectorAll('#aePresetChips .chip');
        chips.forEach(c => c.classList.toggle('active', c.dataset.preset === preset));
        const custom = document.getElementById('aeCustomTiming');
        const hint = document.getElementById('aePresetHint');
        if (preset === 'custom') {
          if (custom) custom.style.display = 'block';
          if (hint) hint.textContent = 'Pick each timing below';
          return;
        }
        if (custom) custom.style.display = 'none';
        _setChipVal('setupDelay', String(setupMs));
        _setChipVal('autoEraseDelay', String(delayMs));
        _setChipVal('autoEraseCooldown', String(cooldownMs));
        if (hint) {
          const fmt = ms => { const s = Math.round(ms/1000); if (s < 60) return s + 's'; const m = Math.round(s/60); return m < 60 ? m + 'm' : Math.round(m/60) + 'h'; };
          const labels = { paranoid: 'Paranoid', balanced: 'Balanced', relaxed: 'Relaxed' };
          hint.textContent = labels[preset] + ' — ' + fmt(setupMs) + ' arm / ' + fmt(delayMs) + ' abort / ' + fmt(cooldownMs) + ' cooldown';
        }
      }
      function _matchAePresetFromValues() {
        const s = _chipVal('setupDelay'), d = _chipVal('autoEraseDelay'), c = _chipVal('autoEraseCooldown');
        const presets = document.querySelectorAll('#aePresetChips .chip[data-preset]');
        let matched = 'custom';
        presets.forEach(p => {
          if (p.dataset.preset === 'custom') return;
          if (p.dataset.setup === s && p.dataset.delay === d && p.dataset.cooldown === c) matched = p.dataset.preset;
        });
        const p = Array.from(presets).find(x => x.dataset.preset === matched);
        if (p) _applyAePreset(matched, p.dataset.setup, p.dataset.delay, p.dataset.cooldown);
        else _applyAePreset('custom');
      }
      document.addEventListener('click', (e) => {
        const presetChip = e.target.closest('#aePresetChips .chip[data-preset]');
        if (presetChip) {
          const p = presetChip.dataset.preset;
          if (p === 'custom') _applyAePreset('custom');
          else _applyAePreset(p, presetChip.dataset.setup, presetChip.dataset.delay, presetChip.dataset.cooldown);
          return;
        }
        const chip = e.target.closest('.chip-row .chip');
        if (!chip) return;
        const row = chip.closest('.field-row');
        if (!row) return;
        row.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        if (['setupDelay','autoEraseDelay','autoEraseCooldown'].includes(row.dataset.field)) {
          _matchAePresetFromValues();
        }
      });
      async function saveAutoEraseConfig() {
      try {
        const enabled = document.getElementById('autoEraseEnabled').checked;
        const delay = _chipVal('autoEraseDelay');
        const cooldown = _chipVal('autoEraseCooldown');
        const vibrationsRequired = _chipVal('vibrationsRequired');
        const detectionWindow = _chipVal('detectionWindow');
        const setupDelay = _chipVal('setupDelay');

        console.log('[AUTOERASE] Sending:', {enabled, delay, cooldown, vibrationsRequired, detectionWindow, setupDelay});

        const fd = new FormData();
        fd.append('enabled', enabled);
        fd.append('delay', delay);
        fd.append('cooldown', cooldown);
        fd.append('vibrationsRequired', vibrationsRequired);
        fd.append('detectionWindow', detectionWindow);
        fd.append('setupDelay', setupDelay);

        const response = await fetch('/config/autoerase', {
          method: 'POST',
          body: fd
        });

        console.log('[AUTOERASE] Response status:', response.status);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.text();
        console.log('[AUTOERASE] Success:', data);
        document.getElementById('autoEraseStatus').textContent = 'Config saved: ' + data;
        toast('Configuration saved', 'success');
        updateAutoEraseStatus();
      } catch (error) {
        console.error('[AUTOERASE] Error:', error);
        document.getElementById('autoEraseStatus').textContent = 'ERROR: ' + error.message;
        toast('Failed to save: ' + error.message, 'error');
      }
    }
      
      function updateEraseProgress(message, percentage) {
        const progressBar = document.getElementById('eraseProgressBar');
        const progressText = document.getElementById('eraseProgressText');
        const progressDetails = document.getElementById('eraseProgressDetails');
        if (progressBar) {
          progressBar.style.width = percentage + '%';
        }
        if (progressText) {
          progressText.textContent = message;
        }
        if (progressDetails) {
          progressDetails.innerHTML += `<div>${new Date().toLocaleTimeString()}: ${message}</div>`;
          progressDetails.scrollTop = progressDetails.scrollHeight;
        }
      }
      
      function pollEraseProgress() {
        const poll = setInterval(() => {
          fetch('/erase/progress').then(response => response.json()).then(data => {
            updateEraseProgress(data.message, data.percentage);
            if (data.status === 'COMPLETE') {
              clearInterval(poll);
              finalizeEraseProcess(true);
            } else if (data.status === 'ERROR') {
              clearInterval(poll);
              finalizeEraseProcess(false, data.error);
            } else if (data.status === 'CANCELLED') {
              clearInterval(poll);
              hideEraseProgressModal();
              toast('Secure erase cancelled', 'info');
            }
          }).catch(error => {
            clearInterval(poll);
            finalizeEraseProcess(false, 'Communication error');
          });
        }, 1000);
      }
      
      function finalizeEraseProcess(success, error = null) {
        if (success) {
          updateEraseProgress('Secure erase completed successfully', 100);
          toast('All data has been securely destroyed', 'success');
          setTimeout(() => {
            hideEraseProgressModal();
            window.location.reload();
          }, 3000);
        } else {
          updateEraseProgress('Secure erase failed: ' + error, 0);
          toast('Erase operation failed: ' + error, 'error');
          setTimeout(() => {
            hideEraseProgressModal();
          }, 5000);
        }
      }
      
      function hideEraseProgressModal() {
        const modal = document.getElementById('eraseProgressModal');
        if (modal) {
          document.body.removeChild(modal);
        }
      }

      function rssiColorFor(rssi) {
        const v = parseInt(rssi);
        if (v >= -50) return 'var(--succ)';
        if (v >= -70) return 'var(--txt)';
        return 'var(--mut)';
      }

      function isRandomMac(mac) {
        if (!mac || mac.length < 2) return false;
        const b = parseInt(mac.substr(0, 2), 16);
        if (isNaN(b)) return false;
        return (b & 0x02) !== 0 && (b & 0x01) === 0;
      }

      let identityMap = {};
      let identityMapFetchedAt = 0;
      async function refreshIdentityMap(force) {
        const now = Date.now();
        if (!force && (now - identityMapFetchedAt) < 8000) return;
        identityMapFetchedAt = now;
        const r = await fetch('/api/identity-map').catch(err => { console.warn('identity-map fetch failed', err); return null; });
        if (!r || !r.ok) return;
        const j = await r.json().catch(err => { console.warn('identity-map parse failed', err); return null; });
        if (j) identityMap = j;
      }

      function identityBadge(mac) {
        if (!mac) return '';
        const id = identityMap[mac.toUpperCase()];
        if (!id) return '';
        return '<span title="Linked to identity ' + id + ' by randomization scanner" style="background:var(--c-known);color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:600;margin-left:6px;vertical-align:middle;letter-spacing:0.5px;font-family:monospace;">' + id + '</span>';
      }

      function randBadge(mac) {
        const linked = identityBadge(mac);
        if (linked) return linked;
        if (!isRandomMac(mac)) return '';
        return '<span title="Locally-administered (randomized) MAC" style="background:var(--c-rand);color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:600;margin-left:6px;vertical-align:middle;letter-spacing:0.5px;">RAND</span>';
      }

      function _resEmpty(msg, icon) {
        const svg = icon === 'ok'
          ? '<svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
          : '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
        return '<div class="res-empty">' + svg + '<div>' + msg + '</div></div>';
      }
      function _resStat(label, value, cls) {
        return '<div class="res-stat' + (cls ? ' ' + cls : '') + '"><div class="res-stat-lab">' + label +
          '</div><div class="res-stat-val">' + value + '</div></div>';
      }
      function _resKv(label, value, cls) {
        return '<div class="res-kv' + (cls ? ' ' + cls : '') + '"><div class="res-kv-lab">' + label +
          '</div><div class="res-kv-val">' + value + '</div></div>';
      }

      function parseAndStyleResults(text) {
        if (!text || text.trim() === '' || text.includes('None yet') || text.includes('No scan data')) {
          return _resEmpty('No scan data yet. Start a scan from the Scan tab.');
        }

        let html = '';

        if (text.includes('=== Triangulation Results') || text.includes('Weighted GPS Trilateration')) {
          html = parseTriangulationResults(text);
        } else if(text.includes('MAC Randomization Detection Results')) {
          html = parseRandomizationResults(text);
        } else if (text.includes('Baseline not yet established') || text.includes('Baseline Detection Results')) {
          html = parseBaselineResults(text);
        } else if (text.includes('Deauth Detection Results') || text.includes('Deauth Attack Detection Results')) {
          html = parseDeauthResults(text);
        } else if (text.includes('Drone Detection Results')) {
          html = parseDroneResults(text);
        } else if (text.includes('Counter-Surveillance / Find My')) {
          html = parseCounterSurveilResults(text);
        } else if (text.includes('Probes:') && text.includes('SSIDs:')) {
          html = parseProbeResults(text);
        } else if (text.includes('Target Hits:') || text.match(/^(WiFi|BLE)\s+[A-F0-9:]/m)) {
          html = parseDeviceScanResults(text);
        } else {
          html = '<div class="res-card"><pre style="margin:0;background:transparent;border:none;padding:0;white-space:pre-wrap;">' + text + '</pre></div>';
        }

        return html;
      }

      function parseTriangulationResults(text) {
        let html = '';
        const headerSection = text.split('---')[0];
        if (headerSection.includes('=== Triangulation Results ===')) {
          const targetMatch = headerSection.match(/Target MAC: ([A-F0-9:]+)/);
          const durationMatch = headerSection.match(/Duration: (\d+)s/);
          const elapsedMatch = headerSection.match(/Elapsed: (\d+)s/);
          const nodesMatch = headerSection.match(/Reporting Nodes: (\d+)/);
          const syncMatch = headerSection.match(/Clock Sync: (.+)/);

          html += '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
          html += '<svg viewBox="0 0 24 24"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>Triangulation Results</div></div>';
          if (targetMatch) html += '<div class="res-mac acc" style="margin-bottom:12px;"><span class="res-note-lab">Target</span>' + targetMatch[1] + randBadge(targetMatch[1]) + '</div>';
          html += '<div class="res-stats">';
          if (durationMatch) html += _resStat('Duration', durationMatch[1] + 's');
          if (elapsedMatch) html += _resStat('Elapsed', elapsedMatch[1] + 's');
          if (nodesMatch) html += _resStat('Nodes', nodesMatch[1]);
          html += '</div>';
          if (syncMatch) {
            const syncVerified = syncMatch[1].includes('VERIFIED');
            html += '<div class="res-note ' + (syncVerified ? '' : 'warn') + '" style="margin-bottom:0;"><span class="res-note-lab">Clock Sync</span>' + syncMatch[1] + '</div>';
          }
          html += '</div>';
        }

        if (text.includes('No Mesh Nodes Responding')) {
          html += '<div class="res-callout danger"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><div><div class="res-callout-title">No Mesh Nodes Responding</div><div class="res-callout-body">No mesh nodes responded to the triangulation request. Check mesh connectivity.</div></div></div>';
        }
        if (text.includes('TRIANGULATION IMPOSSIBLE') || text.includes('none have GPS')) {
          html += '<div class="res-callout warn"><svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><div><div class="res-callout-title">Triangulation Impossible</div><div class="res-callout-body">Nodes responded but none have GPS coordinates. Enable GPS on at least 3 nodes.</div></div></div>';
        }
        if (text.includes('Insufficient GPS Nodes')) {
          html += '<div class="res-callout warn"><svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><div><div class="res-callout-title">Waiting for More GPS Nodes</div><div class="res-callout-body">Triangulation requires at least 3 GPS-equipped nodes. Collecting data...</div></div></div>';
        }

        const nodeSection = text.split('--- Node Reports ---')[1]?.split('---')[0];
        if (nodeSection) {
          html += '<details class="res-section" open><summary><span class="res-caret">&#9654;</span>Node Reports</summary><div class="res-section-body">';
          const nodeLines = nodeSection.split('\n').filter(l => l.trim() && l.includes(':'));
          nodeLines.forEach(line => {
            const nodeMatch = line.match(/^([^:]+):/);
            if (!nodeMatch) return;
            let rssiMatch = line.match(/Filtered=([-\d.]+)dBm/) || line.match(/RSSI=([-\d.]+)dBm/);
            const hitsMatch = line.match(/Hits=(\d+)/);
            const signalMatch = line.match(/Signal=([\d.]+)%/);
            if (!rssiMatch && !hitsMatch && !signalMatch) return;
            const nodeId = nodeMatch[1].trim();
            const gpsMatch = line.match(/GPS=([-\d.]+),([-\d.]+)/);
            const hdopMatch = line.match(/HDOP=([\d.]+)/);
            const isGPS = gpsMatch !== null;
            const distMatch = line.match(/Dist=([\d.]+)m/);

            html += '<div class="res-card' + (isGPS ? ' ok' : '') + '"><div class="res-card-head"><div class="res-mac" style="font-family:inherit;">' + nodeId + '</div>';
            html += '<span class="res-badge ' + (isGPS ? 'ok' : '') + '">' + (isGPS ? 'GPS' : 'No GPS') + '</span></div>';
            html += '<div class="res-kvs">';
            if (rssiMatch) { const rv = parseFloat(rssiMatch[1]); const rc = rv > -60 ? 'var(--succ)' : rv > -75 ? 'var(--warn)' : 'var(--dang)'; html += '<div class="res-kv"><div class="res-kv-lab">RSSI</div><div class="res-kv-val" style="color:' + rc + '">' + rssiMatch[1] + '<small style="font-size:11px;color:var(--mut);"> dBm</small></div></div>'; }
            if (hitsMatch) html += _resKv('Hits', hitsMatch[1]);
            if (signalMatch) { const sv = parseFloat(signalMatch[1]); const sc = sv >= 70 ? 'var(--succ)' : sv >= 50 ? 'var(--warn)' : 'var(--dang)'; html += '<div class="res-kv"><div class="res-kv-lab">Quality</div><div class="res-kv-val" style="color:' + sc + '">' + signalMatch[1] + '%</div></div>'; }
            if (distMatch) html += _resKv('Distance', distMatch[1] + 'm');
            html += '</div>';
            if (isGPS) { html += '<div class="res-note"><span class="res-note-lab">Location</span><span style="font-family:ui-monospace,monospace;color:var(--acc);">' + gpsMatch[1] + ', ' + gpsMatch[2] + '</span>' + (hdopMatch ? ' &middot; HDOP <strong>' + hdopMatch[1] + '</strong>' : '') + '</div>'; }
            html += '</div>';
          });
          html += '</div></details>';
        }

        const validationSection = text.split('--- GPS-RSSI Distance Validation ---')[1]?.split('---')[0];
        if (validationSection) {
          html += '<details class="res-section" open><summary><span class="res-caret">&#9654;</span>GPS-RSSI Validation</summary><div class="res-section-body">';
          const valLines = validationSection.split('\n').filter(l => l.trim() && (l.includes('<->') || l.includes('Avg error')));
          valLines.forEach(line => {
            if (line.includes('<->')) {
              const ok = line.includes('✓');
              const cleanLine = line.replace(/✓|✗/g, '').trim();
              html += '<div class="res-note ' + (ok ? '' : 'danger') + '"><span style="color:' + (ok ? 'var(--succ)' : 'var(--dang)') + ';font-weight:700;margin-right:8px;">' + (ok ? '✓' : '✗') + '</span>' + cleanLine + '</div>';
            } else if (line.includes('Avg error')) {
              const errorMatch = line.match(/([\d.]+)%/);
              const qualityMatch = line.match(/\(([^)]+)\)/);
              if (errorMatch) {
                const ev = parseFloat(errorMatch[1]);
                const ec = ev < 25 ? 'var(--succ)' : ev < 50 ? 'var(--warn)' : 'var(--dang)';
                html += '<div class="res-kv" style="border-color:' + ec + ';"><div class="res-kv-lab">Average Error</div><div class="res-kv-val" style="color:' + ec + ';font-size:20px;">' + errorMatch[1] + '%</div>' + (qualityMatch ? '<div class="res-line" style="margin-top:4px;"><strong>' + qualityMatch[1] + '</strong></div>' : '') + '</div>';
              }
            }
          });
          html += '</div></details>';
        }

        const positionMatch = text.match(/ESTIMATED POSITION[^:]*:([\s\S]*?)(?:===|$)/);
        const positionSection = positionMatch ? positionMatch[1] : null;
        if (positionSection) {
          const latMatch = positionSection.match(/Latitude:\s*([-\d.]+)/);
          const lonMatch = positionSection.match(/Longitude:\s*([-\d.]+)/);
          const confMatch = positionSection.match(/Confidence:\s*([\d.]+)%/);
          const uncertaintyMatch = positionSection.match(/Uncertainty.*?±([\d.]+)m/);
          const methodMatch = positionSection.match(/Method:\s*([^\n]+)/);

          html += '<div class="res-card acc"><div class="res-mac" style="font-family:inherit;color:var(--acc);"><svg viewBox="0 0 24 24" width="18" height="18" style="stroke:var(--acc);fill:none;vertical-align:-3px;margin-right:6px;"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>Position Estimated</div>';
          if (latMatch && lonMatch) {
            html += '<div class="res-coord">';
            html += _resKv('Latitude', '<span class="mono">' + latMatch[1] + '</span>');
            html += _resKv('Longitude', '<span class="mono">' + lonMatch[1] + '</span>');
            html += '</div><div class="res-kvs">';
            if (confMatch) { const cv = parseFloat(confMatch[1]); const cc = cv >= 70 ? 'var(--succ)' : cv >= 50 ? 'var(--warn)' : 'var(--dang)'; html += '<div class="res-kv"><div class="res-kv-lab">Confidence</div><div class="res-kv-val" style="color:' + cc + '">' + confMatch[1] + '%</div></div>'; }
            if (uncertaintyMatch) html += _resKv('Uncertainty (CEP68)', '±' + uncertaintyMatch[1] + 'm');
            html += '</div>';
            if (methodMatch) html += '<div class="res-note"><span class="res-note-lab">Method</span>' + methodMatch[1] + '</div>';
            const mapsUrl = 'https://www.google.com/maps?q=' + latMatch[1] + ',' + lonMatch[1];
            html += '<div style="margin-top:12px;"><a href="' + mapsUrl + '" target="_blank" rel="noopener" class="res-cta"><svg viewBox="0 0 24 24"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>Open in Google Maps</a></div>';
          }
          html += '</div>';
        }
        return html;
      }

      function parseRandomizationResults(text) {
        const headerMatch = text.match(/Active Sessions: (\d+)/);
        const identitiesMatch = text.match(/Device Identities: (\d+)/);

        let html = '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
        html += '<svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>Randomized Device Tracer</div></div>';
        html += '<div class="res-stats">';
        if (headerMatch) html += _resStat('Active Sessions', headerMatch[1]);
        if (identitiesMatch) html += _resStat('Linked Identities', identitiesMatch[1]);
        html += '</div></div>';

        const trackBlocks = text.split(/(?=Track ID:)/g).filter(b => b.includes('Track ID'));
        trackBlocks.forEach((block) => {
          const trackMatch = block.match(/Track ID:\s*([^\n]+)/);
          const typeMatch = block.match(/Type:\s*([^\n]+)/);
          const nameMatch = block.match(/Name:\s*([^\n]+)/);
          const ssidMatch = block.match(/SSID:\s*([^\n]+)/);
          const rssiMatch = block.match(/RSSI: avg ([-\d]+) dBm\s+min ([-\d]+)\s+max ([-\d]+)/);
          const probesMatch = block.match(/Probes:\s*(\d+)/);
          const macsMatch = block.match(/MACs linked:\s*(\d+)/);
          const confMatch = block.match(/Confidence:\s*([\d.]+)/);
          const sessionsMatch = block.match(/Sessions:\s*(\d+)/);
          const intervalConMatch = block.match(/Interval consistency:\s*([\d.]+)/);
          const rssiConMatch = block.match(/RSSI consistency:\s*([\d.]+)/);
          const channelsMatch = block.match(/Channels:\s*(\d+)/);
          const seqTrackMatch = block.match(/Sequence tracking:\s*(.+)/);
          const firstSeenMatch = block.match(/First seen:\s*(\d+)s ago/);
          const lastSeenMatch = block.match(/Last seen:\s*(\d+)s ago/);
          const realMacMatch = block.match(/Real MAC:\s*([A-F0-9:]+)/);
          const vendorMatch = block.match(/Vendor:\s*([^\n]+)/);
          const mfrDataMatch = block.match(/Mfr data:\s*([^\n]+)/);
          const macsListMatch = block.match(/MACs:\s*(.+)/);
          if (!trackMatch) return;

          const trackId = trackMatch[1].trim();
          const isBLE = typeMatch && typeMatch[1].trim() === 'BLE';
          const deviceType = isBLE ? 'BLE' : 'WiFi';
          const macCount = macsMatch ? macsMatch[1] : '0';
          const confidence = confMatch ? (parseFloat(confMatch[1]) * 100).toFixed(0) : '0';
          const anchorMacMatch = block.match(/Anchor MAC:\s*([A-F0-9:]+)/);
          const anchorMac = anchorMacMatch ? anchorMacMatch[1] : (macsListMatch ? macsListMatch[1].split(',')[0].trim() : '');
          const avgRssi = rssiMatch ? parseInt(rssiMatch[1]) : null;
          const rssiColor = avgRssi !== null ? (avgRssi >= -50 ? 'var(--succ)' : avgRssi >= -70 ? 'var(--warn)' : 'var(--dang)') : 'var(--mut)';
          const confVal = parseInt(confidence);
          const confColor = confVal >= 75 ? 'var(--succ)' : confVal >= 50 ? 'var(--warn)' : 'var(--dang)';

          html += '<details class="res-section" data-type="' + deviceType + '" style="padding:0;">';
          html += '<summary style="padding:15px 16px;justify-content:space-between;font-weight:400;color:var(--txt);">';
          html += '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;flex-wrap:wrap;">';
          html += '<span class="res-caret" style="color:var(--acc);">&#9654;</span>';
          if (anchorMac) html += '<span class="res-mac acc" style="font-size:13px;">' + anchorMac + '</span>' + randBadge(anchorMac);
          html += '<span class="res-badge ' + (isBLE ? 'ble' : 'wifi') + '">' + deviceType + '</span>';
          if (nameMatch) html += '<span data-name="' + nameMatch[1].trim() + '" class="res-line" style="color:var(--txt);">' + nameMatch[1].trim() + '</span>';
          if (ssidMatch) html += '<span data-ssid="' + ssidMatch[1].trim() + '" style="color:var(--acc);font-size:11px;">&quot;' + ssidMatch[1].trim() + '&quot;</span>';
          if (vendorMatch) html += '<span class="res-line" style="font-size:11px;">' + vendorMatch[1].trim() + '</span>';
          html += '<span class="res-line" style="font-size:11px;">' + macCount + ' MAC' + (macCount !== '1' ? 's' : '') + '</span>';
          html += '</div>';
          html += '<div style="display:flex;align-items:center;gap:14px;flex-shrink:0;">';
          if (avgRssi !== null) html += '<div class="res-metric"><span class="res-metric-val" style="font-size:14px;color:' + rssiColor + '">' + avgRssi + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div>';
          html += '<div class="res-metric"><span class="res-metric-val" style="font-size:14px;color:' + confColor + '">' + confidence + '<small>%</small></span><span class="res-metric-lab">Conf</span></div>';
          html += '</div></summary>';

          html += '<div style="padding:0 16px 16px 16px;border-top:1px solid var(--bord);">';
          html += '<div class="res-kvs">';
          if (sessionsMatch) html += _resKv('Sessions', sessionsMatch[1]);
          if (probesMatch) html += _resKv('Probes', probesMatch[1]);
          if (rssiMatch) html += '<div class="res-kv"><div class="res-kv-lab">RSSI min/avg/max</div><div class="res-kv-val sm" style="color:' + rssiColor + '">' + rssiMatch[2] + ' / ' + rssiMatch[1] + ' / ' + rssiMatch[3] + ' dBm</div></div>';
          if (lastSeenMatch) { const seenTxt = firstSeenMatch ? firstSeenMatch[1] + 's &rarr; ' + lastSeenMatch[1] + 's ago' : lastSeenMatch[1] + 's ago'; html += '<div class="res-kv"><div class="res-kv-lab">Seen</div><div class="res-kv-val sm">' + seenTxt + '</div></div>'; }
          if (intervalConMatch) html += _resKv('Interval Consistency', (parseFloat(intervalConMatch[1]) * 100).toFixed(0) + '%');
          if (rssiConMatch) html += _resKv('RSSI Stability', (parseFloat(rssiConMatch[1]) * 100).toFixed(0) + '%');
          if (channelsMatch) html += _resKv('Unique Channels', channelsMatch[1]);
          if (realMacMatch) html += '<div class="res-kv danger" style="grid-column:1/-1"><div class="res-kv-lab" style="color:var(--dang)">Real MAC Leaked</div><div class="res-kv-val mono" style="color:var(--dang)">' + realMacMatch[1] + '</div></div>';
          html += '</div>';

          if (seqTrackMatch) html += '<div class="res-note"><span class="res-note-lab">Sequence Tracking</span><span style="font-family:ui-monospace,monospace;">' + seqTrackMatch[1].trim() + '</span></div>';
          if (vendorMatch || mfrDataMatch) { html += '<div class="res-note"><span class="res-note-lab">Manufacturer</span>'; if (vendorMatch) html += '<strong>' + vendorMatch[1].trim() + '</strong>'; if (mfrDataMatch) html += ' <span style="font-family:ui-monospace,monospace;color:var(--mut);">' + mfrDataMatch[1].trim() + '</span>'; html += '</div>'; }
          html += '<div class="res-note ok" style="border-left-color:var(--succ);"><span class="res-note-lab">Track ID</span><span style="font-family:ui-monospace,monospace;color:var(--acc);font-weight:600;">' + trackId + '</span></div>';

          if (macsListMatch) {
            const macsList = macsListMatch[1];
            const moreMatch = macsList.match(/\(\+(\d+) more\)/);
            const cleanMacs = macsList.replace(/\s*\(\+\d+ more\)/, '');
            const macs = cleanMacs.split(',').map(m => m.trim()).filter(m => m.length > 0);
            html += '<details class="res-rows" open style="margin-top:11px;"><summary style="list-style:none;cursor:pointer;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);">MAC Addresses (' + (moreMatch ? macCount : macs.length) + ')</summary><div style="margin-top:8px;">';
            macs.forEach((mac) => {
              const isFirst = mac === anchorMac;
              html += '<div class="res-row"><span style="color:' + (isFirst ? 'var(--acc)' : 'var(--mut)') + '">' + mac + randBadge(mac) + '</span>' + (isFirst ? '<span class="res-badge ok">Anchor</span>' : '') + '</div>';
            });
            if (moreMatch) html += '<div class="res-more">+ ' + moreMatch[1] + ' more</div>';
            html += '</div></details>';
          }
          html += '</div></details>';
        });
        return html;
      }

      function toggleTrackCollapse(cardId) {
        const content = document.getElementById(cardId + 'Content');
        const icon = document.getElementById(cardId + 'Icon');
        
        if (content.style.display === 'none') {
          content.style.display = 'block';
          icon.style.transform = 'rotate(0deg)';
          icon.textContent = '▼';
        } else {
          content.style.display = 'none';
          icon.style.transform = 'rotate(-90deg)';
          icon.textContent = '▶';
        }
      }

      function parseBaselineResults(text) {
        function makeDeviceCard(type, mac, rssi, channel, name) {
          let c = '<div class="res-card device-card" data-type="' + type + '" data-channel="' + (channel || '0') + '">';
          c += '<div class="res-row-main"><span class="res-mac">' + mac + randBadge(mac) + '</span>';
          c += '<div class="res-meta">';
          if (name && name !== 'Unknown') c += '<span>Name: <strong>' + name + '</strong></span>';
          c += '<span class="res-badge ' + (type === 'BLE' ? 'ble' : 'wifi') + '">' + type + '</span>';
          if (channel) c += '<span class="res-badge">CH ' + channel + '</span>';
          c += '</div>';
          c += '<div class="res-metric"><span class="res-metric-val" style="color:' + rssiColorFor(rssi) + '">' + rssi + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div>';
          c += '</div></div>';
          return c;
        }

        let html = '';
        var isEstablishing = text.includes('Baseline not yet established');
        if (isEstablishing) {
          const devSection = text.split('=== BASELINE DEVICES (Cached in RAM) ===')[1];
          const deviceLines = devSection ? devSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/)) : [];
          if (deviceLines.length === 0) return _resEmpty('Cataloging devices…');
          html += '<div class="baseline-marker" style="display:none;"></div>';
          deviceLines.forEach(line => {
            const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:[-\d]+dBm\s+Max:[-\d]+dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
            if (m) html += makeDeviceCard(m[1], m[2], m[3], m[5], m[6]);
          });
          return html;
        }

        const anomalyCountMatch = text.match(/Total anomalies: (\d+)/);
        const anomalyCount = anomalyCountMatch ? parseInt(anomalyCountMatch[1]) : 0;

        if (anomalyCount > 0) {
          html += '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
          html += '<svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Baseline Anomalies</div></div>';
          html += '<div class="res-stats">' + _resStat('Anomalies', anomalyCount, 'danger') + '</div></div>';

          const anomalySection = text.split('=== ANOMALIES DETECTED ===')[1];
          if (anomalySection) {
            anomalySection.split('\n').filter(l => l.trim() && !l.includes('Total anomalies')).forEach(line => {
              const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI:([-\d]+)dBm(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?\s+-\s+(.+)$/);
              if (!m) return;
              const [_, type, mac, rssi, channel, name, reason] = m;
              html += '<div class="res-card alert device-card" data-type="' + type + '" data-channel="' + (channel || '0') + '">';
              html += '<div class="res-row-main"><span class="res-mac warn">' + mac + randBadge(mac) + '</span>';
              html += '<div class="res-meta"><span class="res-badge ' + (type === 'BLE' ? 'ble' : 'wifi') + '">' + type + '</span>';
              if (channel) html += '<span class="res-badge">CH ' + channel + '</span>';
              if (name) html += '<span>Name: <strong>' + name + '</strong></span>';
              html += '</div>';
              html += '<div class="res-metric"><span class="res-metric-val" style="color:' + rssiColorFor(rssi) + '">' + rssi + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div>';
              html += '</div>';
              html += '<div class="res-note warn">' + reason + '</div></div>';
            });
          }
        } else {
          html += _resEmpty('No anomalies detected.', 'ok');
        }

        const baselineSection = text.split('=== BASELINE DEVICES (Cached in RAM) ===')[1]?.split('===')[0];
        if (baselineSection) {
          const deviceLines = baselineSection.split('\n').filter(l => l.trim() && l.match(/^(WiFi|BLE)/));
          if (deviceLines.length > 0) {
            html += '<details class="res-section"><summary><span class="res-caret">&#9654;</span>Baseline Devices (' + deviceLines.length + ' cached)</summary><div class="res-section-body">';
            deviceLines.forEach(line => {
              const m = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+Avg:([-\d]+)dBm\s+Min:[-\d]+dBm\s+Max:[-\d]+dBm\s+Hits:(\d+)(?:\s+CH:(\d+))?(?:\s+"([^"]+)")?/);
              if (m) html += makeDeviceCard(m[1], m[2], m[3], m[5], m[6]);
            });
            html += '</div></details>';
          }
        }
        return html;
      }

      function parseDeauthResults(text) {
        let html = '';
        const durationMatch = text.match(/Duration: (.+)/);
        const deauthMatch = text.match(/Deauth frames: (\d+)/);
        const disassocMatch = text.match(/Disassoc frames: (\d+)/);
        const totalMatch = text.match(/Total attacks: (\d+)/);
        const targetsMatch = text.match(/Targets attacked: (\d+)/);

        html += '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
        html += '<svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Deauth Attack Detection</div></div>';
        html += '<div class="res-stats">';
        if (durationMatch) html += _resStat('Duration', durationMatch[1]);
        if (deauthMatch) html += _resStat('Deauth Frames', deauthMatch[1], parseInt(deauthMatch[1]) > 0 ? 'danger' : '');
        if (disassocMatch) html += _resStat('Disassoc Frames', disassocMatch[1], parseInt(disassocMatch[1]) > 0 ? 'danger' : '');
        if (totalMatch) html += _resStat('Total Attacks', totalMatch[1], parseInt(totalMatch[1]) > 0 ? 'danger' : '');
        if (targetsMatch) html += _resStat('Targets', targetsMatch[1]);
        html += '</div></div>';

        if (text.includes('No attacks detected')) {
          html += _resEmpty('No deauth attacks detected.', 'ok');
          return html;
        }

        const lines = text.split('\n');
        let currentTarget = null;
        let currentTargetHtml = '';
        let inSourcesList = false;

        function flush() {
          if (currentTarget) { html += currentTargetHtml + '</div></div>'; }
          currentTarget = null; currentTargetHtml = ''; inSourcesList = false;
        }

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const targetMatch = line.match(/^([A-F0-9:]+|\[BROADCAST\])\s+Total=(\d+)\s+Broadcast=(\d+)\s+Targeted=(\d+)\s+LastRSSI=([-\d]+)dBm\s+CH=(\d+)/);
          if (targetMatch) {
            flush();
            const [_, target, total, broadcast, targeted, rssi, channel] = targetMatch;
            const isBroadcast = target === '[BROADCAST]';

            currentTargetHtml = '<div class="res-card alert">';
            currentTargetHtml += '<div class="res-card-head"><div class="res-mac warn">' + target + (isBroadcast ? '<span class="res-badge warn">Broadcast Attack</span>' : randBadge(target)) + '</div></div>';
            currentTargetHtml += '<div class="res-kvs">';
            currentTargetHtml += _resKv('Total Attacks', '<span style="color:var(--dang)">' + total + '</span>');
            currentTargetHtml += _resKv('Broadcast', '<span style="color:var(--dang)">' + broadcast + '</span>');
            currentTargetHtml += _resKv('Targeted', '<span style="color:var(--warn)">' + targeted + '</span>');
            currentTargetHtml += '<div class="res-kv"><div class="res-kv-lab">Signal / Channel</div><div class="res-kv-val sm">' + rssi + ' dBm / CH' + channel + '</div></div>';
            currentTargetHtml += '</div>';
            currentTargetHtml += '<div class="res-rows"><div class="res-rows-lab">Attack Sources</div>';
            currentTarget = target;
            inSourcesList = true;
            continue;
          }

          if (inSourcesList && line.trim().startsWith('←')) {
            const sourceMatch = line.match(/← ([A-F0-9:]+) \((\d+)x\)/);
            if (sourceMatch) {
              currentTargetHtml += '<div class="res-row"><span>&larr; ' + sourceMatch[1] + randBadge(sourceMatch[1]) + '</span><span class="res-row-meta">' + sourceMatch[2] + ' attacks</span></div>';
            }
          }
          if (inSourcesList && line.trim().startsWith('...')) {
            const moreMatch = line.match(/\((\d+) more attackers\)/);
            if (moreMatch) currentTargetHtml += '<div class="res-more">+ ' + moreMatch[1] + ' more attackers</div>';
          }
          if (line.trim() === '' && currentTarget) flush();
        }
        flush();

        const finalMoreMatch = text.match(/\.\.\. \((\d+) more targets\)/);
        if (finalMoreMatch) html += '<div class="res-more" style="border:1px dashed var(--bord);border-radius:8px;padding:12px;">+ ' + finalMoreMatch[1] + ' more targets</div>';

        return html;
      }

      function parseDroneResults(text) {
        let html = '';
        const totalMatch = text.match(/Total detections: (\d+)/);
        const uniqueMatch = text.match(/Unique drones: (\d+)/);

        html += '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
        html += '<svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>Drone Detection</div></div>';
        html += '<div class="res-stats">';
        if (totalMatch) html += _resStat('Total Detections', totalMatch[1]);
        if (uniqueMatch) html += _resStat('Unique Drones', uniqueMatch[1]);
        html += '</div></div>';

        const droneBlocks = text.split(/(?=MAC:)/g).filter(b => b.includes('MAC:'));
        droneBlocks.forEach(block => {
          const macMatch = block.match(/MAC: ([A-F0-9:]+)/);
          const uavMatch = block.match(/UAV ID: (.+)/);
          const typeMatch = block.match(/UA Type: (.+)/);
          const rssiMatch = block.match(/RSSI: ([-\d]+) dBm/);
          const locMatch = block.match(/Location: (.+)/);
          const altMatch = block.match(/Altitude MSL: (.+)/);
          const hgtMatch = block.match(/Height AGL: (.+)/);
          const speedMatch = block.match(/Speed: (.+?)  Vert: (.+)/);
          const hdgMatch = block.match(/Heading: (.+)/);
          const statusMatch = block.match(/Status: (.+)/);
          const opLocMatch = block.match(/Operator: ([-\d.]+), ([-\d.]+)/);
          const opIdMatch = block.match(/Operator ID: (.+)/);
          const descMatch = block.match(/Description: (.+)/);
          const authMatch = block.match(/Auth: type (\d+) ts (\d+)/);
          if (!macMatch) return;

          html += '<div class="res-card acc">';
          html += '<div class="res-row-main"><span class="res-mac acc">' + macMatch[1] + randBadge(macMatch[1]) + '</span>';
          html += '<div class="res-meta">';
          if (uavMatch) html += '<span>UAV ID: <strong>' + uavMatch[1] + '</strong></span>';
          if (typeMatch) html += '<span class="res-badge">' + typeMatch[1] + '</span>';
          html += '</div>';
          if (rssiMatch) html += '<div class="res-metric"><span class="res-metric-val">' + rssiMatch[1] + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div>';
          html += '</div>';

          const kvs = [];
          if (locMatch) kvs.push(['Location', locMatch[1]]);
          if (altMatch) kvs.push(['Altitude MSL', altMatch[1]]);
          if (hgtMatch) kvs.push(['Height AGL', hgtMatch[1]]);
          if (speedMatch) kvs.push(['Speed', speedMatch[1] + ' <small style="color:var(--mut);font-weight:500;">(Vert ' + speedMatch[2] + ')</small>']);
          if (hdgMatch) kvs.push(['Heading', hdgMatch[1]]);
          if (statusMatch) kvs.push(['Status', statusMatch[1]]);
          if (kvs.length) {
            html += '<div class="res-kvs">';
            kvs.forEach(k => html += '<div class="res-kv"><div class="res-kv-lab">' + k[0] + '</div><div class="res-kv-val sm">' + k[1] + '</div></div>');
            html += '</div>';
          }

          if (opLocMatch || opIdMatch || descMatch || authMatch) {
            html += '<div class="res-note"><span class="res-note-lab">Operator</span>';
            const bits = [];
            if (opLocMatch) bits.push('<strong>' + opLocMatch[1] + ', ' + opLocMatch[2] + '</strong>');
            if (opIdMatch) bits.push('ID <strong>' + opIdMatch[1] + '</strong>');
            if (descMatch) bits.push('“' + descMatch[1] + '”');
            if (authMatch) bits.push('Auth type ' + authMatch[1] + ', ts ' + authMatch[2]);
            html += bits.join(' &middot; ') + '</div>';
          }
          html += '</div>';
        });

        return html;
      }

      function parseCounterSurveilResults(text) {
        const air = text.match(/AirTags \/ Find My present: (\d+)/);
        const fol = text.match(/Potential followers: (\d+)/);
        const trk = text.match(/BLE trackers: (\d+)/);
        let html = '<div class="res-hero"><div class="res-hero-top"><div class="res-hero-title">';
        html += '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Counter-Surveillance</div></div>';
        html += '<div class="res-stats">';
        html += _resStat('AirTags / Find My', air ? air[1] : '0', (air && parseInt(air[1]) > 0) ? 'warn' : '');
        html += _resStat('BLE Trackers', trk ? trk[1] : '0');
        html += _resStat('Followers', fol ? fol[1] : '0', (fol && parseInt(fol[1]) > 0) ? 'danger' : '');
        html += '</div></div>';

        let section = '', items = 0, m;
        text.split('\n').forEach(function(line) {
          if (/AirTags \/ Find My present:/.test(line)) { section = 'air'; return; }
          if (/Potential followers:/.test(line)) { section = 'fol'; return; }
          if (/BLE trackers:/.test(line)) { section = 'trk'; return; }
          const t = line.trim();
          if (!t) return;
          if (section === 'air' && (m = t.match(/^([0-9A-Fa-f:]{17})\s+RSSI (-?\d+)dBm\s+(\S+)\s+seen (\d+)x/))) {
            const near = m[3] === 'owner-nearby';
            html += '<div class="res-card' + (near ? ' acc' : ' danger') + '"><div class="res-row-main"><span class="res-mac acc">' + m[1] + '<span class="res-badge">Find My</span></span>';
            html += '<div class="res-meta"><span>' + (near ? 'owner nearby' : '<span class="res-badge danger">Separated (lost mode)</span>') + '</span><span>seen <strong>' + m[4] + '</strong>x</span></div>';
            html += '<div class="res-metric"><span class="res-metric-val" style="color:' + rssiColorFor(m[2]) + '">' + m[2] + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div></div></div>';
            items++;
          } else if (section === 'fol' && (m = t.match(/^id ([0-9a-f]+)\s+seen (\d+)x\s+owner-absent (\d+)%\s+clusters (\d+)(.*)$/))) {
            const al = /ALERTED/.test(m[5]);
            html += '<div class="res-card' + (al ? ' danger' : '') + '"><div class="res-row-main"><span class="res-mac acc">follower ' + m[1] + (al ? '<span class="res-badge danger">Follower</span>' : '') + '</span>';
            html += '<div class="res-meta"><span>seen <strong>' + m[2] + '</strong>x</span><span>' + m[4] + ' node cluster' + (m[4] === '1' ? '' : 's') + '</span></div>';
            html += '<div class="res-metric"><span class="res-metric-val" style="color:' + (parseInt(m[3]) >= 70 ? 'var(--dang)' : 'var(--txt)') + '">' + m[3] + '<small>%</small></span><span class="res-metric-lab">Owner-absent</span></div></div></div>';
            items++;
          } else if (section === 'trk' && (m = t.match(/^([0-9A-Fa-f:]{17})\s+(\S+)\s+RSSI (-?\d+)dBm\s+seen (\d+)x\s+persist (\d+)(.*)$/))) {
            const fw = /FOLLOWING/.test(m[6]);
            html += '<div class="res-card' + (fw ? ' danger' : '') + '"><div class="res-row-main"><span class="res-mac acc">' + m[1] + '<span class="res-badge">' + m[2] + '</span></span>';
            html += '<div class="res-meta"><span>seen <strong>' + m[4] + '</strong>x</span><span>persistence ' + m[5] + '</span>' + (fw ? '<span class="res-badge danger">Following</span>' : '') + '</div>';
            html += '<div class="res-metric"><span class="res-metric-val" style="color:' + rssiColorFor(m[3]) + '">' + m[3] + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div></div></div>';
            items++;
          }
        });
        if (items === 0) html += _resEmpty('No AirTags, trackers, or followers detected yet.', 'ok');
        return html;
      }

      function parseProbeLine(raw) {
        const line = raw.replace(/^(WiFi|BLE)\s+/, '').trim();
        const macM = line.match(/([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/);
        if (!macM) return null;
        const mac = macM[1].toUpperCase();
        const rssiM = line.match(/RSSI=(-?\d+)dBm/);
        const chM = line.match(/CH=(\d+)/);
        const countM = line.match(/(?:^|\s)x(\d+)(?:\s|$)/);
        const apM = line.match(/AP="([^"]*)"/);
        const apBssidM = line.match(/APBSSID=([0-9A-Fa-f:]+)/);
        const knownM = line.match(/\[KNOWN:seen=(\d+)\s+sessions=(\d+)\s+last=([^\]]+)\]/);
        const randomized = isRandomMac(mac) || /\bRand(?:omized)?\b/.test(line);
        let vendor = '';
        let vm = line.match(/CH=\d+\s+([A-Za-z][\w-]*)/);
        if (!vm) vm = line.match(/^[0-9A-Fa-f:]{17}\s+([A-Za-z][\w-]*)/);
        if (vm && ['probes','AP','Rand','Randomized','RSSI','Unknown'].indexOf(vm[1]) < 0) vendor = vm[1];
        const ssids = [];
        const probesM = line.match(/probes:((?:~?"[^"]*",?)+)/);
        if (probesM) { for (const m of probesM[1].matchAll(/(~?)"([^"]*)"/g)) ssids.push({ name: m[2], ghost: m[1] === '~' }); }
        return {
          mac, rssi: rssiM ? rssiM[1] : null, ch: chM ? chM[1] : '', count: countM ? parseInt(countM[1]) : 1,
          vendor, randomized, ssids, ap: apM ? apM[1] : '', apBssid: apBssidM ? apBssidM[1] : '',
          known: knownM ? { seen: knownM[1], sessions: knownM[2], last: knownM[3] } : null
        };
      }

      function groupProbeDevices(devs) {
        const groups = new Map();
        const broadcast = [];
        const grp = (name) => {
          if (!groups.has(name)) groups.set(name, { name, devices: [], anyPresent: false, apResponded: false, apBssid: '' });
          return groups.get(name);
        };
        for (const d of devs) {
          let placed = false;
          for (const s of d.ssids) {
            const g = grp(s.name);
            if (g.devices.indexOf(d) < 0) g.devices.push(d);
            if (!s.ghost) g.anyPresent = true;
            placed = true;
          }
          if (d.ap) {
            const g = grp(d.ap);
            if (g.devices.indexOf(d) < 0) g.devices.push(d);
            g.apResponded = true; g.anyPresent = true;
            if (d.apBssid && !g.apBssid) g.apBssid = d.apBssid;
            placed = true;
          }
          if (!placed) broadcast.push(d);
        }
        return { groups, broadcast };
      }

      function renderProbeClientCard(d) {
        let h = '<div class="res-card' + (d.known ? ' acc' : '') + '">';
        h += '<div class="res-row-main"><span class="res-mac">' + d.mac + randBadge(d.mac);
        if (d.vendor && !d.randomized && !isRandomMac(d.mac)) h += '<span class="res-badge">' + d.vendor + '</span>';
        if (d.ch) h += '<span class="res-badge">CH' + d.ch + '</span>';
        if (d.count > 1) h += '<span class="res-badge acc">x' + d.count + '</span>';
        if (d.ap) h += '<span class="res-badge ok">Client</span>';
        if (d.known) h += '<span class="res-badge known">Known</span>';
        h += '</span>';
        if (d.ssids.length > 1) {
          h += '<div class="res-meta"><span>also probing ';
          h += d.ssids.map(s => s.name).join(', ');
          h += '</span></div>';
        }
        if (d.rssi !== null) h += '<div class="res-metric"><span class="res-metric-val" style="color:' + rssiColorFor(d.rssi) + '">' + d.rssi + '<small> dBm</small></span><span class="res-metric-lab">RSSI</span></div>';
        h += '</div>';
        if (d.known) h += '<div class="res-sub"><span style="color:var(--c-known);">Seen <strong>' + d.known.seen + '</strong> times across <strong>' + d.known.sessions + '</strong> sessions</span> &middot; last: ' + d.known.last + '</div>';
        h += '</div>';
        return h;
      }

      function renderProbeGroups(devs) {
        const { groups, broadcast } = groupProbeDevices(devs);
        const arr = Array.from(groups.values()).sort((a, b) => b.devices.length - a.devices.length || a.name.localeCompare(b.name));
        let html = '';
        for (const g of arr) {
          const away = !g.apResponded && !g.anyPresent;
          const n = g.devices.length;
          html += '<details class="res-section" open><summary><span class="res-caret">&#9654;</span>';
          html += '<span data-ssid="' + g.name + '">' + g.name + '</span>';
          html += '<span class="res-badge ' + (away ? 'warn' : 'acc') + '">' + n + ' client' + (n === 1 ? '' : 's') + '</span>';
          if (g.apResponded) html += '<span class="res-badge ok">AP present</span>';
          else if (away) html += '<span class="res-badge warn">Away</span>';
          if (g.apBssid) html += '<span class="res-badge">' + g.apBssid + '</span>';
          html += '</summary><div class="res-section-body">';
          for (const d of g.devices) html += renderProbeClientCard(d);
          html += '</div></details>';
        }
        if (broadcast.length) {
          html += '<details class="res-section"><summary><span class="res-caret">&#9654;</span><span>Broadcast probes (no specific network)</span>';
          html += '<span class="res-badge">' + broadcast.length + ' device' + (broadcast.length === 1 ? '' : 's') + '</span></summary><div class="res-section-body">';
          for (const d of broadcast) html += renderProbeClientCard(d);
          html += '</div></details>';
        }
        return html;
      }

      function parseProbeResults(text) {
        let html = '';
        savedDevicesLoaded = false;
        const lines = text.split('\n');
        const headerLine = lines[0] || '';
        const statsLine = lines[1] || '';
        const inProgress = headerLine.includes('IN PROGRESS');

        const devMatch = statsLine.match(/Devices:\s*(\d+)/);
        const probeMatch = statsLine.match(/Probes:\s*(\d+)/);
        const ssidMatch = statsLine.match(/SSIDs:\s*(\d+)/);
        const savedMatch = statsLine.match(/Saved:\s*(\d+)/);

        html += '<div class="res-hero">';
        html += '<div class="res-hero-top"><div class="res-hero-title">';
        html += '<svg viewBox="0 0 24 24"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>';
        html += 'Probe Detection</div>';
        if (inProgress) html += '<span class="res-scanning">Scanning</span>';
        html += '</div><div class="res-stats">';
        if (devMatch) html += _resStat('Devices', devMatch[1]);
        if (probeMatch) html += _resStat('Probes', probeMatch[1]);
        if (ssidMatch) html += _resStat('SSIDs', ssidMatch[1]);
        if (savedMatch) html += _resStat('Saved', savedMatch[1]);
        html += '</div></div>';

        if (savedMatch && parseInt(savedMatch[1]) > 0) {
          html += '<div id="savedDevicesPanel" style="margin-bottom:14px;">';
          html += '<div style="display:flex;align-items:center;gap:8px;">';
          html += '<div id="savedDevicesToggle" onclick="toggleSavedDevices()" class="res-section" style="flex:1;cursor:pointer;padding:11px 14px;margin:0;">';
          html += '<div style="display:flex;align-items:center;gap:9px;font-size:13px;font-weight:700;color:var(--acc);">';
          html += '<span id="savedDevicesArrow" class="res-caret">&#9654;</span><span>Saved Devices (' + savedMatch[1] + ')</span></div></div>';
          html += '<button onclick="clearSavedDevices()" class="btn danger" style="padding:9px 14px;">Clear</button>';
          html += '</div>';
          html += '<div id="savedDevicesList" style="display:none;margin-top:8px;max-height:340px;overflow-y:auto;"></div>';
          html += '</div>';
        }

        let deviceLines = [];
        for (let i = 2; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          if (line.startsWith('SSIDs seen')) break;
          if (line.startsWith('WiFi') || line.startsWith('BLE')) deviceLines.push(line);
        }

        const devs = [];
        for (const line of deviceLines) { const d = parseProbeLine(line); if (d) devs.push(d); }
        if (devs.length > 0) html += renderProbeGroups(devs);
        else html += _resEmpty('No probing devices detected yet.', 'ok');

        return html;
      }

      let savedDevicesLoaded = false;
      let savedDevicesOpen = false;
      function toggleSavedDevices() {
        const list = document.getElementById('savedDevicesList');
        const arrow = document.getElementById('savedDevicesArrow');
        if (!list || !arrow) return;
        savedDevicesOpen = !savedDevicesOpen;
        list.style.display = savedDevicesOpen ? 'block' : 'none';
        arrow.style.transform = savedDevicesOpen ? 'rotate(90deg)' : '';
        if (savedDevicesOpen && !savedDevicesLoaded) {
          list.innerHTML = '<div style="padding:12px;color:var(--mut);font-size:11px;">Loading...</div>';
          fetch('/api/probedb').then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(devices => {
            savedDevicesLoaded = true;
            if (!devices.length) {
              list.innerHTML = '<div style="padding:12px;color:var(--mut);font-size:11px;">No saved devices</div>';
              return;
            }
            let h = '';
            devices.sort((a, b) => b.last - a.last);
            for (const d of devices) {
              const isRand = d.rand;
              const border = isRand ? 'var(--c-rand)' : 'var(--bord)';
              h += '<div style="padding:6px 10px;border-bottom:1px solid var(--bord);font-size:11px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;">';
              h += '<span style="font-family:monospace;font-weight:bold;color:var(--txt);min-width:140px;">' + d.mac + '</span>';
              h += randBadge(d.mac);
              if (d.vendor && !isRandomMac(d.mac)) {
                h += '<span style="color:var(--mut);font-size:10px;">' + d.vendor + '</span>';
              }
              h += '<span style="color:var(--mut);font-size:10px;">' + d.rssi + 'dBm</span>';
              h += '<span style="color:var(--mut);font-size:10px;">x' + d.seen + '</span>';
              h += '<span style="color:var(--mut);font-size:10px;">' + d.sessions + ' sess</span>';
              if (d.ssids && d.ssids.length > 0) {
                for (const s of d.ssids) {
                  h += '<span data-ssid="' + s + '" style="background:var(--surf);border:1px solid var(--bord);padding:1px 5px;border-radius:3px;font-size:9px;color:var(--txt);">' + s + '</span>';
                }
              }
              h += '</div>';
            }
            list.innerHTML = h;
            if (typeof privacyMode !== 'undefined' && privacyMode) applyPrivacyToElement(list);
          }).catch((e) => {
            console.error('probedb load failed', e);
            list.innerHTML = '<div style="padding:12px;color:var(--c-err);font-size:11px;">Failed to load (' + (e && e.message ? e.message : 'error') + ')</div>';
          });
        }
      }

      function clearSavedDevices() {
        if (!confirm('Clear all saved probe devices?')) return;
        fetch('/api/probedb/clear', { method: 'POST' }).then(r => {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          savedDevicesLoaded = false;
          savedDevicesOpen = false;
          const list = document.getElementById('savedDevicesList');
          const arrow = document.getElementById('savedDevicesArrow');
          if (list) { list.style.display = 'none'; list.innerHTML = ''; }
          if (arrow) arrow.style.transform = '';
          if (typeof toast === 'function') toast('Saved devices cleared');
        }).catch(e => { if (typeof toast === 'function') toast('Clear failed: ' + e.message, 'warning'); });
      }

      function getTargetTokens() {
        const el = document.getElementById('list');
        if (!el || !el.value) return [];
        return el.value.split('\n')
          .map(l => l.trim().toUpperCase())
          .filter(l => l && !l.startsWith('#') && /^[0-9A-F]{2}(:[0-9A-F]{2}){2,5}$/.test(l));
      }

      function macIsTarget(mac, tokens) {
        if (!tokens || !tokens.length) return false;
        const m = (mac || '').toUpperCase();
        return tokens.some(t => t.length >= 17 ? m === t : m.startsWith(t + ':'));
      }

      function parseDeviceScanResults(text) {
        let html = '';

        const modeMatch = text.match(/Mode: ([^\s]+)/);
        const durationMatch = text.match(/Duration: ([^\n]+)/);
        const hitsMatch = text.match(/Target Hits: (\d+)/);
        const uniqueMatch = text.match(/Unique devices: (\d+)/);

        if (modeMatch || durationMatch || hitsMatch || uniqueMatch) {
          html += '<div id="deviceScanHeader" class="res-hero">';
          html += '<div class="res-hero-top"><div class="res-hero-title">';
          html += '<svg viewBox="0 0 24 24"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>';
          html += 'Device Discovery</div></div>';
          const _dsN = [modeMatch, durationMatch, hitsMatch, uniqueMatch].filter(Boolean).length;
          html += '<div class="res-stats" data-n="' + _dsN + '">';
          if (modeMatch) html += _resStat('Mode', modeMatch[1]);
          if (durationMatch) html += _resStat('Duration', durationMatch[1]);
          if (hitsMatch) html += _resStat('Target Hits', hitsMatch[1], parseInt(hitsMatch[1]) > 0 ? 'ok' : '');
          if (uniqueMatch) html += _resStat('Unique Devices', uniqueMatch[1]);
          html += '</div></div>';
        }

        const lines = text.split('\n');
        let inProbeSection = false;
        let probeLines = [];
        const targetTokens = getTargetTokens();
        let targetHtml = '';
        let normalHtml = '';

        lines.forEach(line => {
          if (line.startsWith('--- Probe Intelligence')) { inProbeSection = true; return; }
          if (inProbeSection) { if (line.trim().length > 0) probeLines.push(line.trim()); return; }

          const match = line.match(/^(WiFi|BLE)\s+([A-F0-9:]+)\s+RSSI=([-\d]+)dBm(?:\s+CH=(\d+))?(?:\s+"([^"]*)")?/);
          if (!match) return;

          const type = match[1];
          const mac = match[2];
          const rssi = match[3];
          const channel = match[4] || '';
          const name = match[5] || 'Unknown';
          const isApple = / APPLE(?:\s|$)/.test(line);

          const rssiColor = rssiColorFor(rssi);
          const isTarget = macIsTarget(mac, targetTokens);
          const cls = 'res-card device-card' + (isTarget ? ' target is-target' : '');

          let card = '<div class="' + cls + '" data-type="' + type + '" data-channel="' + (channel || '0') + '" data-target="' + (isTarget ? '1' : '0') + '">';
          card += '<div class="res-row-main">';
          card += '<span class="res-mac">';
          if (isTarget) card += '<span class="res-badge target">TARGET</span>';
          card += mac + randBadge(mac);
          if (isApple) card += '<span class="res-badge muted" title="Apple device (advertises Apple 0x004C continuity)">APPLE</span>';
          card += '</span>';
          card += '<div class="res-meta">';
          card += '<span>Name: <strong>' + name + '</strong></span>';
          card += '<span class="res-badge ' + (type === 'BLE' ? 'ble' : 'wifi') + '">' + type + '</span>';
          if (channel) card += '<span class="res-badge">CH ' + channel + '</span>';
          card += '</div>';
          card += '<div class="res-metric">';
          card += '<span class="res-metric-val" style="color:' + rssiColor + '">' + rssi + '<small> dBm</small></span>';
          card += '<span class="res-metric-lab">RSSI</span>';
          card += '</div>';
          card += '</div>';
          card += '</div>';

          if (isTarget) targetHtml += card; else normalHtml += card;
        });

        html += targetHtml + normalHtml;

        if (probeLines.length > 0) {
          const pdevs = [];
          for (const pl of probeLines) { const d = parseProbeLine(pl); if (d) pdevs.push(d); }
          if (pdevs.length > 0) {
            html += '<div class="res-hero-title" style="margin:18px 0 12px;">Probe Intelligence &mdash; grouped by network (' + pdevs.length + ' probing device' + (pdevs.length === 1 ? '' : 's') + ')</div>';
            html += renderProbeGroups(pdevs);
          }
        }

        return html;
      }

      function resetRandomizationDetection() {
        if (!confirm('Reset all randomization detection data?')) return;
        
        fetch('/randomization/reset', { method: 'POST' })
          .then(r => r.text())
          .then(data => {
            toast(data, 'success');
          })
          .catch(err => toast('Error: ' + err, 'error'));
      }

      function toast(msg, type = 'info') {
        const wrap = document.getElementById('toast');
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        const typeLabels = {
          'success': 'SUCCESS',
          'error': 'ERROR',
          'warning': 'WARNING',
          'info': 'INFO'
        };
        el.innerHTML = `<div class="toast-content"><div class="toast-title">[${typeLabels[type] || typeLabels.info}]</div><div class="toast-message">${msg}</div></div>`;
        wrap.appendChild(el);
        requestAnimationFrame(() => el.classList.add('show'));
        const duration = type === 'success' ? 10000 : (type === 'error' ? 8000 : 4000);
        setTimeout(() => {
          el.classList.remove('show');
          setTimeout(() => wrap.removeChild(el), 300);
        }, duration);
      }
      
      function updateAutoEraseStatus() {
        fetch('/config/autoerase').then(response => response.json()).then(data => {
          const statusDiv = document.getElementById('autoEraseStatus');
          let statusText = '';
          let statusClass = '';

          const checkbox = document.getElementById('autoEraseEnabled');
          if (checkbox) {
            checkbox.checked = data.enabled;
          }
          if (typeof data.setupDelay !== 'undefined') _setChipVal('setupDelay', data.setupDelay);
          if (typeof data.delay !== 'undefined') _setChipVal('autoEraseDelay', data.delay);
          if (typeof data.cooldown !== 'undefined') _setChipVal('autoEraseCooldown', data.cooldown);
          if (typeof data.vibrationsRequired !== 'undefined') _setChipVal('vibrationsRequired', data.vibrationsRequired);
          if (typeof data.detectionWindow !== 'undefined') _setChipVal('detectionWindow', data.detectionWindow);
          _matchAePresetFromValues();

          if (!data.enabled) {
            statusText = 'DISABLED - Manual erase only';
            statusClass = 'status-disabled';
          } else if (data.inSetupMode) {
            const elapsed = data.currentTime - data.setupStartTime;
            const remaining = Math.max(0, Math.floor((data.setupDelay - elapsed) / 1000));
            statusText = `SETUP MODE - Activating in ${remaining}s`;
            statusClass = 'status-setup';
          } else if (data.tamperActive) {
            statusText = 'TAMPER DETECTED - Auto-erase in progress';
            statusClass = 'status-danger';
          } else {
            statusText = 'ACTIVE - Monitoring for tampering';
            statusClass = 'status-active';
          }
          statusDiv.textContent = statusText;
          statusDiv.className = statusClass;
        }).catch(error => {
          document.getElementById('autoEraseStatus').textContent = 'Status unavailable';
        });
      }
      
      async function cancelErase() {
        const response = await fetch('/erase/cancel', { method: 'POST' });
        const data = await response.text();
        document.getElementById('eraseStatus').innerHTML = '<pre>' + data + '</pre>';
      }
      
      function pollEraseStatus() {
        const poll = setInterval(() => {
          fetch('/erase/status').then(response => response.text()).then(status => {
            document.getElementById('eraseStatus').innerHTML = '<pre>Status: ' + status + '</pre>';
            if (status === 'COMPLETED') {
              clearInterval(poll);
              // Show persistent success message
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:var(--c-ok);font-weight:bold;">SUCCESS: Secure erase completed successfully</pre>';
              toast('All data has been securely destroyed', 'success');
              // Clear the form
              document.getElementById('eraseConfirm').value = '';
            } else if (status.startsWith('FAILED')) {
              clearInterval(poll);
              document.getElementById('eraseStatus').innerHTML = '<pre style="color:var(--c-err);font-weight:bold;">FAILED: ' + status + '</pre>';
              toast('Secure erase failed: ' + status, 'error');
            }
          }).catch(error => {
            clearInterval(poll);
            toast('Status check failed: ' + error, 'error');
          });
        }, 1000); // Check every second for faster feedback
      }
      
      let _erasePskSet = false;
      function refreshPskStatus() {
        fetch('/erase/psk-status').then(r => r.json()).then(d => {
          _erasePskSet = !!d.pskSet;
          const badge = document.getElementById('erasePskBadge');
          const hint = document.getElementById('eraseConfirmHint');
          const input = document.getElementById('eraseConfirm');
          const fwHint = document.getElementById('factoryWipeHint');
          const fwInput = document.getElementById('factoryWipeConfirm');
          if (_erasePskSet) {
            if (badge) { badge.textContent = 'PSK SET — auth required'; badge.className = 'psk-badge set'; }
            if (hint) hint.textContent = 'Enter erase PSK';
            if (input) input.placeholder = 'erase PSK';
            if (fwHint) fwHint.textContent = 'Enter erase PSK';
            if (fwInput) fwInput.placeholder = 'erase PSK';
          } else {
            if (badge) { badge.textContent = 'NO PSK — using default code'; badge.className = 'psk-badge unset'; }
            if (hint) hint.textContent = 'Type WIPE_ALL_DATA exactly (set a PSK via mesh CONFIG_ERASE_PSK:<key>)';
            if (input) input.placeholder = 'WIPE_ALL_DATA';
            if (fwHint) fwHint.textContent = 'Type FACTORY_WIPE exactly';
            if (fwInput) fwInput.placeholder = 'FACTORY_WIPE';
          }
        }).catch(()=>{});
      }
      function pollSecureState() {
        fetch('/secure/status').then(r => r.text()).then(s => {
          const badge = document.getElementById('eraseStateBadge');
          const abort = document.getElementById('eraseAbortBtn');
          if (!badge || !abort) return;
          if (s && s.startsWith('TAMPER_ACTIVE')) {
            const sec = (s.split(':')[1] || '').replace('s','');
            badge.style.display = 'inline-flex';
            badge.textContent = 'TAMPER ACTIVE — ' + sec + 's to wipe';
            abort.style.display = 'block';
          } else {
            badge.style.display = 'none';
            abort.style.display = 'none';
          }
        }).catch(()=>{});
      }
      setInterval(pollSecureState, 5000);

      const _factoryResetTiers = {
        full: {btn: 'WIPE EVERYTHING', hint: 'Wipes ALL SD data files + resets NVS to factory defaults. Device reboots.', warn: 'FINAL WARNING: Wipes ALL SD data + resets NVS config. Device will reboot. Proceed?'},
        config: {btn: 'RESET CONFIG', hint: 'Resets NVS config (AP creds, node ID, targets, allowlist, RF/mesh/auto-erase, erase PSK) to defaults. Captured SD data is KEPT. Device reboots.', warn: 'Resets all settings to factory defaults (captured data is kept). Device will reboot. Proceed?'},
        data: {btn: 'ERASE DATA', hint: 'Erases ALL captured SD data (probedb, probes, deauth, drones, baseline, logs, incidents). Settings/identity are KEPT. Device reboots.', warn: 'Erases all captured data on SD (settings are kept). Device will reboot. Proceed?'}
      };
      function updateFactoryResetTier() {
        const tier = document.getElementById('factoryResetTier').value;
        const t = _factoryResetTiers[tier] || _factoryResetTiers.full;
        const btn = document.getElementById('factoryWipeBtn');
        const hint = document.getElementById('factoryResetScopeHint');
        if (btn) btn.textContent = t.btn;
        if (hint) hint.textContent = t.hint;
      }
      function requestFactoryWipe() {
        const tier = document.getElementById('factoryResetTier').value;
        const t = _factoryResetTiers[tier] || _factoryResetTiers.full;
        const code = document.getElementById('factoryWipeConfirm').value;
        const expected = _erasePskSet ? null : 'FACTORY_WIPE';
        if (!code || (expected && code !== expected)) {
          toast(_erasePskSet ? 'Enter erase PSK' : 'Type FACTORY_WIPE exactly to confirm', 'error');
          return;
        }
        if (!window.confirm(t.warn)) {
          return;
        }
        toast(t.btn + ' started...', 'warning');
        fetch('/factory-wipe', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'confirm=' + encodeURIComponent(code) + '&tier=' + encodeURIComponent(tier)
        }).then(response => response.text()).then(data => {
          const el = document.getElementById('factoryWipeStatus');
          el.style.display = 'block';
          el.innerHTML = '<pre>' + data + '</pre>';
          toast('Reset complete — rebooting', 'success');
        }).catch(error => {
          toast('Reset error: ' + error, 'error');
        });
      }

      function requestErase() {
        const confirm = document.getElementById('eraseConfirm').value;
        const expected = _erasePskSet ? null : 'WIPE_ALL_DATA';
        if (!confirm || (expected && confirm !== expected)) {
          toast(_erasePskSet ? 'Enter erase PSK' : 'Type WIPE_ALL_DATA exactly to confirm', 'error');
          return;
        }
        if (!window.confirm('FINAL WARNING: This will permanently destroy all data. Are you absolutely sure?')) {
          return;
        }
        toast('Initiating secure erase operation...', 'warning');
        fetch('/erase/request', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `confirm=${encodeURIComponent(confirm)}`
        }).then(response => response.text()).then(data => {
          document.getElementById('eraseStatus').style.display = 'block';
          document.getElementById('eraseStatus').innerHTML = '<pre>' + data + '</pre>';
          toast('Secure erase started', 'info');
          // Start polling for status
          pollEraseStatus();
        }).catch(error => {
          toast('Network error: ' + error, 'error');
        });
      }

      function formatDiagnostics(text) {
        if (!text || text.trim() === '') return '<div style="color:var(--mut);padding:20px;text-align:center;">No data</div>';
        
        const lines = text.trim().split('\n');
        let html = '<div class="stat-grid">';
        
        lines.forEach(line => {
          const parts = line.split(':');
          if (parts.length >= 2) {
            const label = parts[0].trim();
            const value = parts.slice(1).join(':').trim();
            
            html += '<div class="stat-item">';
            html += '<div class="stat-label">' + label + '</div>';
            html += '<div class="stat-value">' + value + '</div>';
            html += '</div>';
          }
        });
        
        html += '</div>';
        return html;
      }

      function formatDiagGrid(text,type){
        if(!text||text.trim()==='')return'<div style="color:var(--mut);text-align:center;padding:20px;">No data</div>';
        let html='<div class="diag-grid">';
        const lines=text.trim().split('\n');
        lines.forEach(line=>{
          const parts=line.split(':');
          if(parts.length<2)return;
          const label=parts[0].trim();
          const value=parts.slice(1).join(':').trim();
          html+='<div class="stat-item">';
          html+='<div class="stat-label">'+label+'</div>';
          html+='<div class="stat-value" style="font-size:14px;">'+value+'</div>';
          html+='</div>';
        });
        html+='</div>';
        return html;
      }

      let tickStart = 0;
      async function tick() {
        if (tickRunning) {
          if (Date.now() - tickStart > 15000) tickRunning = false;
          else return;
        }
        tickRunning = true;
        tickStart = Date.now();
        try {
          refreshIdentityMap(false);
          const diagResponse = await fetch('/diag').catch(() => null);
          if (!diagResponse) return;
          const diagText = await diagResponse.text();
          const isScanning = diagText.includes('Scanning: yes');
          const isTriActive = diagText.includes('Triangulating: yes');
          radioBusy = isScanning || isTriActive;
          const taskMatch = diagText.match(/Task Type: ([^\n]+)/);
          radioBusyTask = taskMatch ? taskMatch[1].trim() : '';
          const sections = diagText.split('\n');
          meshEnabled = diagText.includes('Mesh: Enabled');
          updateMeshUI();
          const hbMatch = diagText.match(/Heartbeat: \w+ (\d+)min/);
          hbEnabled = diagText.includes('Heartbeat: Enabled');
          if (hbMatch) { const inp = document.getElementById('hbIntervalInput'); if (inp && document.activeElement !== inp) inp.value = hbMatch[1]; }
          updateHbUI();
          vibrationEnabled = diagText.includes('Vibration Broadcasts: Enabled');
          updateVibrationUI();

          // --- System page updates: immediately after /diag, no extra fetches ---
          let hardware = '';
          let network = '';
          sections.forEach(line => {
            if (line.includes('WiFi Frames')) {
              const match = line.match(/(\d+)/);
              if (match) { document.getElementById('wifiFrames').innerText = match[1]; pushSpark('wifiFrames', parseInt(match[1], 10)); }
            }
            if (line.includes('BLE Frames')) {
              const match = line.match(/(\d+)/);
              if (match) { document.getElementById('bleFrames').innerText = match[1]; pushSpark('bleFrames', parseInt(match[1], 10)); }
            }
            if (line.includes('Devices Found')) {
              const match = line.match(/(\d+)/);
              if (match) document.getElementById('totalHits').innerText = match[1];
            }
            if (line.includes('Unique devices') && radioBusyTask !== 'baseline') {
              const match = line.match(/(\d+)/);
              if (match) { document.getElementById('uniqueDevices').innerText = match[1]; pushSpark('uniqueDevices', parseInt(match[1], 10)); }
            }
            if (line.includes('ESP32 Temp')) {
              const match = line.match(/([\d.]+)C/);
              if (match) { document.getElementById('temperature').innerHTML = match[1] + '<small>°C</small>'; pushSpark('temperature', parseFloat(match[1])); }
            }
            if (line.includes('SD Card') || line.includes('GPS') || line.includes('RTC') || line.includes('Vibration')) {
              hardware += line + '\n';
            } else if (line.includes('AP IP') || line.includes('Mesh') || line.includes('WiFi Channels')) {
              network += line + '\n';
            }
          });
          document.getElementById('hardwareDiag').innerHTML = formatDiagGrid(hardware, 'hardware');
          document.getElementById('networkDiag').innerHTML = formatDiagGrid(network, 'network');
          window.__lastDiag = Date.now();
          const uptimeMatch = diagText.match(/Up:(\d+):(\d+):(\d+)/);
          if (uptimeMatch) {
            document.getElementById('uptime').innerText = uptimeMatch[1] + ':' + uptimeMatch[2] + ':' + uptimeMatch[3];
          }
          updateStatusIndicators(diagText);
          updateMeshTxIndicator(diagText);

          // --- Optional fetches: only when needed, skip what baseline already handles ---
          const droneActive = diagText.includes('Drone Detection: Active');
          const baselineHandling = !!baselineUpdateInterval;
          const fetchPromises = [];
          if (droneActive) fetchPromises.push(fetch('/drone/status').catch(() => null));
          else fetchPromises.push(Promise.resolve(null));
          if (!baselineHandling && (isScanning || (lastScanningState && !isScanning))) fetchPromises.push(fetch('/results').catch(() => null));
          else fetchPromises.push(Promise.resolve(null));
          const [droneResponse, resultsResponse] = await Promise.all(fetchPromises);
          if (droneResponse) {
            try {
              const droneData = await droneResponse.json();
              document.getElementById('droneStatus').innerText = 'Drone Detection: Active (' + droneData.unique + ' drones)';
              document.getElementById('droneStatus').classList.add('active');
            } catch (e) {}
          }
          if (radioBusyTask === 'baseline' && !baselineHandling) {
            try {
              const bsResp = await fetch('/baseline/stats');
              const bs = await bsResp.json();
              const el = document.getElementById('uniqueDevices');
              const cur = bs.totalDevices;
              if (cur > prevUniqueDevices && prevUniqueDevices > 0) {
                const diff = cur - prevUniqueDevices;
                el.innerHTML = cur + ' <span style="color:var(--succ);font-size:11px;font-weight:normal;">(+' + diff + ' new)</span>';
                el.style.transition = 'color 0.3s';
                el.style.color = 'var(--succ)';
                setTimeout(() => { el.style.color = ''; }, 2000);
              } else {
                el.innerText = cur;
              }
              prevUniqueDevices = cur;
            } catch(e) {}
          }
          const stopAllBtn = document.getElementById('stopAllBtn');
          if (stopAllBtn) {
            stopAllBtn.style.display = isScanning ? 'inline-block' : 'none';
          }
          const resultsElement = document.getElementById('r');
          if (resultsElement && !resultsElement.contains(document.activeElement)) {
            if ((isScanning || (lastScanningState && !isScanning)) && resultsResponse) {
              const resultsText = await resultsResponse.text();
              // Don't regress to empty/placeholder while scanning — server may briefly clear lastResults during task init
              if (isScanning && (!resultsText || resultsText.trim() === '' || resultsText.includes('None yet') || resultsText.includes('No scan data'))) {
                // skip — keep current results visible
              } else if (resultsText !== lastResultsText) {
                lastResultsText = resultsText;
                if (isScanning) {
                  setTimeout(() => {
                    const expandedCards = new Set();
                    const expandedDetails = new Map();
                    const contents = resultsElement.querySelectorAll('[id$="Content"]');
                    for (const content of contents) {
                      if (content.style.display !== 'none') {
                        expandedCards.add(content.id);
                      }
                    }
                    const openDetails = resultsElement.querySelectorAll('details[open]');
                    for (const details of openDetails) {
                      const summary = details.querySelector('summary');
                      if (summary && summary.textContent) {
                        expandedDetails.set(summary.textContent.trim(), true);
                      }
                    }
                    resultsElement.innerHTML = parseAndStyleResults(resultsText);
                    for (const contentId of expandedCards) {
                      const content = document.getElementById(contentId);
                      if (content) {
                        const iconId = contentId.replace('Content', 'Icon');
                        const icon = document.getElementById(iconId);
                        content.style.display = 'block';
                        if (icon) {
                          icon.style.transform = 'rotate(0deg)';
                          icon.textContent = '▼';
                        }
                      }
                    }
                    const allDetails = resultsElement.querySelectorAll('details');
                    for (const details of allDetails) {
                      const summary = details.querySelector('summary');
                      if (summary) {
                        const summaryText = summary.textContent.trim();
                        if (expandedDetails.has(summaryText)) {
                          details.open = true;
                        }
                      }
                    }
                    if (currentSort !== 'default') sortResultsDisplay();
                  }, 0);
                } else {
                  resultsElement.innerHTML = parseAndStyleResults(resultsText);
                  if (currentSort !== 'default') sortResultsDisplay();
                }
              }
            }
          }
          lastScanningState = isScanning;
        } catch (e) {
          console.error('Tick error:', e);
        } finally {
          tickRunning = false;
        }
      }

      // === Incidents panel ===
      function fmtIncUptime(ms){
        const s = Math.floor(ms/1000), h=Math.floor(s/3600), m=Math.floor((s%3600)/60), ss=s%60;
        if (h>0) return h+':'+String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0');
        return String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0');
      }
      function esc(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
      function _atkColor(t){
        t=(t||'').toUpperCase();
        if(t.startsWith('DEAUTH'))return '#ef4444';
        if(t.startsWith('EVILTWIN'))return '#f97316';
        if(t.startsWith('KARMA'))return '#ec4899';
        if(t.startsWith('PMKID'))return '#14b8a6';
        if(t.startsWith('SAE'))return '#eab308';
        if(t.startsWith('BEACON'))return '#f59e0b';
        if(t.startsWith('AUTH_FLOOD'))return '#fb7185';
        if(t.startsWith('ASSOC'))return '#a855f7';
        if(t.startsWith('PROBE')||t==='RECON')return '#38bdf8';
        if(t.startsWith('HSHK')||t.startsWith('KRACK'))return '#84cc16';
        if(t.startsWith('OWE'))return '#22d3ee';
        if(t.startsWith('FRAG'))return '#c084fc';
        if(t.startsWith('TSF'))return '#2dd4bf';
        if(t.startsWith('JAM'))return '#f43f5e';
        if(t.startsWith('MESH'))return '#818cf8';
        if(t.startsWith('PWNA'))return '#fbbf24';
        if(t.startsWith('ATTACKER'))return '#fb923c';
        if(t.startsWith('SSID'))return '#fcd34d';
        if(t.startsWith('BLE')||t.startsWith('AIRTAG')||t.startsWith('TRACK'))return '#94a3b8';
        return '#9ca3af';
      }
      function _incWhen(e){
        if(e.epoch&&e.epoch>946684800){const d=new Date(e.epoch*1000);return d.toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
        return fmtIncUptime(e.ts||0)+' up';
      }
      function _incDetail(e){
        let d=e.raw||'';
        if(e.type&&d.startsWith(e.type+':'))d=d.slice(e.type.length+1);
        if(e.src&&e.src!=='local'&&d.startsWith(e.src))d=d.slice(e.src.length).replace(/^:/,'');
        return d;
      }
      let _incLastHtml = null;
      async function loadIncidents(){
        try {
          const r = await fetch('/api/incidents.json?limit=200');
          if (!r.ok) return;
          const arr = await r.json();
          const ftype = document.getElementById('incFilter').value;
          const fsrc  = document.getElementById('incSrc').value;
          const body = document.getElementById('incBody');
          const filtered = arr.slice().reverse().filter(e =>
            (!ftype || e.type === ftype) &&
            (!fsrc  || (fsrc === 'local' ? e.src === 'local' : e.src !== 'local'))
          );
          document.getElementById('incCount').textContent = filtered.length + ' / ' + arr.length + ' total';
          let html;
          if (filtered.length === 0) {
            html = '<tr><td colspan="5" style="padding:12px;color:var(--mut);">No incidents</td></tr>';
          } else {
            html = '';
            for (const e of filtered) {
              html += '<tr>'
                    + '<td class="sa-when">'+ esc(_incWhen(e)) +'</td>'
                    + '<td><span class="sa-node">'+ esc(e.node) +'</span></td>'
                    + '<td class="sa-mac">'+ esc(e.src) +'</td>'
                    + '<td style="font-weight:600;color:'+_atkColor(e.type)+';">'+ esc(e.type) +'</td>'
                    + '<td class="sa-detail">'+ esc(_incDetail(e)) +'</td>'
                    + '</tr>';
            }
          }
          if (html !== _incLastHtml) {
            body.innerHTML = html;
            _incLastHtml = html;
          }
        } catch(e){ console.error('loadIncidents', e); }
      }
      function downloadIncidents(){ window.open('/api/incidents.jsonl', '_blank'); }
      async function clearIncidents(){
        if (!confirm('Clear all incidents (RAM ring + SD file)?')) return;
        await fetch('/api/incidents', {method:'DELETE'});
        loadIncidents();
      }
      document.getElementById('incFilter').addEventListener('change', loadIncidents);
      document.getElementById('incSrc').addEventListener('change', loadIncidents);
      setInterval(() => { if (pageActive('detect')) loadIncidents(); }, 5000);
      loadIncidents();

      async function sentinelRefresh(){
        try {
          const r = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!r.ok) return;
          const j = await r.json();
          let txt='DISABLED', col='#888';
          if (j.scanning){txt='KILLED (scan active)';col='#f99';}
          else if (j.running){txt='RUNNING';col='#9f9';}
          else if (j.enabled){txt='enabled, task not running';col='#fc6';}
          const el2=document.getElementById('sentStatus2');
          if(el2){el2.textContent=txt;el2.style.color=col;}
          const tb=document.getElementById('sentToggleBtn');
          if(tb){tb.textContent=j.enabled?'Stop':'Start';tb.className=j.enabled?'btn alt':'btn primary';}
        } catch(e){ console.error('sentinelRefresh', e); }
      }
      async function sentinelStart(){
        const r = await fetch('/api/sentinel/start', {method:'POST'});
        if (!r.ok) alert('Start failed: ' + await r.text());
        sentinelRefresh();
      }
      async function sentinelStop(){
        await fetch('/api/sentinel/stop', {method:'POST'});
        sentinelRefresh();
      }
      setInterval(() => { if (pageActive('detect')) sentinelRefresh(); }, 4000);
      sentinelRefresh();

      document.getElementById('triangulate').addEventListener('change', e => {
        document.getElementById('triangulateOptions').style.display = e.target.checked ? 'block' : 'none';
        const secsInput = document.querySelector('input[name="secs"]');
        if (e.target.checked) {
          if (parseInt(secsInput.value) < 20) {
            secsInput.value = 20;
            toast('Triangulation requires minimum 20 seconds');
          }
          secsInput.setAttribute('min', '20');
        } else {
          secsInput.setAttribute('min', '0');
        }
      });

      document.getElementById('f').addEventListener('submit', e => {
        e.preventDefault();
        ajaxForm(e.target, 'Targets saved ✓');
        setTimeout(load, 500);
      });

      document.getElementById('af').addEventListener('submit', e => {
        e.preventDefault();
        ajaxForm(e.target, 'Allowlist saved ✓');
        setTimeout(() => {
          fetch('/allowlist-export').then(r => r.text()).then(t => {
            document.getElementById('wlist').value = t;
            document.getElementById('allowlistCount').textContent = t.split('\n').filter(x => x.trim()).length + ' entries';
          });
        }, 500);
      });

      document.getElementById('nodeForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const input = document.getElementById('nodeId');
        const value = input.value.trim().toUpperCase();
        input.value = value;
        
        if (value === '') {
            toast('Node ID required: 2-5 alphanumeric characters (examples: AB, A1C, XYZ99)', 'error');
            return;
        }
        
        if (value.length < 2) {
            toast('Node ID too short - minimum 2 characters', 'error');
            return;
        }
        
        if (value.length > 5) {
            toast('Node ID too long - maximum 5 characters', 'error');
            return;
        }
        
        if (!/^[A-Z0-9]+$/.test(value)) {
            toast('Only alphanumeric characters (A-Z, 0-9) allowed', 'error');
            return;
        }
        
        ajaxForm(e.target, 'Node ID updated');
        setTimeout(loadNodeId, 500);
      });

      // Debounce state for scan forms
      const scanDebounce = {
        listScan: { inProgress: false, lastSubmit: 0, cooldown: 1000 },
        sniffer: { inProgress: false, lastSubmit: 0, cooldown: 1000 }
      };

      // Unified clear-on-start: wipes the results panel + server-side lastResults
      // BEFORE the new scan's POST so the prior scan's content cannot leak through
      // a tick() that fires between the UI clear and the new task's initial write.
      async function prepScanStart(starterText) {
        const el = document.getElementById('r');
        if (el && !el.contains(document.activeElement)) {
          lastResultsText = '';
          el.innerHTML = parseAndStyleResults(starterText || 'Scan starting...\n');
          switchPage('results');
        }
        try {
          await fetch('/clear-results', { method: 'POST' });
        } catch (err) {
          console.warn('[SCAN] /clear-results failed (continuing — UI was already cleared):', err);
        }
      }

      document.getElementById('s').addEventListener('submit', async e => {
          e.preventDefault();

          if (isRadioBusy()) return;

          const now = Date.now();
          const state = scanDebounce.listScan;

          // Prevent double-submission
          if (state.inProgress) {
              toast('Scan already in progress', 'warning');
              return;
          }

          // Enforce cooldown period
          if (now - state.lastSubmit < state.cooldown) {
              const remaining = Math.ceil((state.cooldown - (now - state.lastSubmit)) / 1000);
              toast(`Please wait ${remaining}s before starting another scan`, 'warning');
              return;
          }

          const fd = new FormData(e.target);
          const submitBtn = e.target.querySelector('button[type="submit"]');

          // Mark as in progress
          state.inProgress = true;
          state.lastSubmit = now;

          // Check if triangulation mode is selected
          const isTriangulation = fd.has('triangulate') && fd.get('triangulate') === '1';

          lastScanStartTime = now;

          // Immediately update UI to show scanning state for ALL scan types
          setScanStatus(isTriangulation ? 'Triangulate' : 'List Scan', 'active');

          // Update button immediately for all scan types
          if (submitBtn) {
              submitBtn.textContent = 'Stop Scan';
              submitBtn.classList.remove('primary');
              submitBtn.classList.add('danger');
              submitBtn.disabled = false;  // Keep enabled so they can stop
              submitBtn.style.opacity = '1';
              submitBtn.style.cursor = 'pointer';
              submitBtn.type = 'button';
              submitBtn.onclick = function(e) {
                  e.preventDefault();
                  lastScanStartTime = 0;
                  fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                      setTimeout(async () => {
                          const refreshedDiag = await fetch('/diag').then(r => r.text());
                          updateStatusIndicators(refreshedDiag);
                      }, 500);
                  });
              };
          }

          {
              const modeVal = parseInt(document.querySelector('#s select[name="mode"]')?.value ?? '2');
              const modeLabel = ['WiFi', 'BLE', 'WiFi+BLE'][modeVal] ?? 'WiFi+BLE';
              await prepScanStart('Target scan starting...\nMode: ' + modeLabel + '\n');
          }

          fetch('/scan', {
            method: 'POST',
            body: fd
          }).then(r => {
            console.log('[SCAN] Response received at', new Date().toISOString());
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            console.log('[SCAN] Response text:', t, 'at', new Date().toISOString());
            toast(t);
            console.log('[SCAN] Forcing tick() at', new Date().toISOString());
            setTimeout(() => {
              console.log('[SCAN] tick() executing at', new Date().toISOString());
              tick();
            }, 100);
          }).catch(err => {
            console.error('[SCAN] Error at', new Date().toISOString(), err);
            toast('Error: ' + err.message, 'error');
          }).finally(() => {
            setTimeout(() => {
              state.inProgress = false;
              // Don't reset button state - we updated it immediately on click
              // and tick() will sync it with the actual backend state
              console.log('[SCAN] State reset at', new Date().toISOString());
            }, 500);
          });
        });

      document.getElementById('detectionMode').addEventListener('change', function() {
        const selectedMethod = this.value;
        const standardControls = document.getElementById('standardDurationControls');
        const baselineControls = document.getElementById('baselineConfigControls');
        const randomizationModeControls = document.getElementById('randomizationModeControls');
        const deviceScanModeControls = document.getElementById('deviceScanModeControls');
        const probeScanModeControls = document.getElementById('probeScanModeControls');
        const cacheBtn = document.getElementById('cacheBtn');
        const resetBaselineBtn = document.getElementById('resetBaselineBtn');
        const clearOldBtn = document.getElementById('clearOldBtn');
        const resetRandBtn = document.getElementById('resetRandBtn');

        cacheBtn.style.display = 'none';
        resetBaselineBtn.style.display = 'none';
        clearOldBtn.style.display = 'none';
        resetRandBtn.style.display = 'none';
        standardControls.style.display = 'none';
        baselineControls.style.display = 'none';
        randomizationModeControls.style.display = 'none';
        deviceScanModeControls.style.display = 'none';
        probeScanModeControls.style.display = 'none';
        document.getElementById('baselineStatus').style.display = 'none';

        if (selectedMethod === 'baseline') {
          baselineControls.style.display = 'block';
          resetBaselineBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = true;
          document.getElementById('baselineMonitorDuration').disabled = false;
          updateBaselineStatus();
          
        } else if (selectedMethod === 'randomization-detection') {
          standardControls.style.display = 'block';
          randomizationModeControls.style.display = 'block';
          clearOldBtn.style.display = 'inline-block';
          resetRandBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
          
        } else if (selectedMethod === 'device-scan') {
          standardControls.style.display = 'block';
          deviceScanModeControls.style.display = 'block';
          cacheBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
          
        } else if (selectedMethod === 'drone-detection') {
          standardControls.style.display = 'block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;

        } else if (selectedMethod === 'probe-scan') {
          standardControls.style.display = 'block';
          probeScanModeControls.style.display = 'block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;

        } else {
          standardControls.style.display = 'block';
          cacheBtn.style.display = 'inline-block';
          document.getElementById('detectionDuration').disabled = false;
          document.getElementById('baselineMonitorDuration').disabled = true;
        }
      });

      document.getElementById('sniffer').addEventListener('submit', async e => {
        e.preventDefault();

        if (isRadioBusy()) return;

        const now = Date.now();
        const state = scanDebounce.sniffer;

        if (state.inProgress) {
          toast('Detection/scan already in progress', 'warning');
          return;
        }

        if (now - state.lastSubmit < state.cooldown) {
          const remaining = Math.ceil((state.cooldown - (now - state.lastSubmit)) / 1000);
          toast(`Please wait ${remaining}s before starting another scan`, 'warning');
          return;
        }

        const fd = new FormData(e.target);
        const _wc = document.getElementById('wifiChannels');
        if (_wc && _wc.value.trim()) fd.append('ch', _wc.value.trim());
        const detectionMethod = fd.get('detection');
        const submitBtn = document.getElementById('startDetectionBtn');
        let endpoint = '/sniffer';

        state.inProgress = true;
        state.lastSubmit = now;
        lastScanStartTime = now;

        const detMethodLabels = {
          'device-scan': 'Device Scan', 'drone-detection': 'Drone Detect',
          'blue-team': 'Blue Team', 'baseline': 'Baseline',
          'randomization-detection': 'Rand Detect', 'probe-detection': 'Probe Detect',
          'counter-surveil': 'Counter-Surveil'
        };
        setScanStatus(detMethodLabels[detectionMethod] || 'Scanning', 'active');

        if (submitBtn) {
            submitBtn.textContent = 'Stop Scanning';
            submitBtn.classList.remove('primary');
            submitBtn.classList.add('danger');
            submitBtn.disabled = false;
            submitBtn.style.opacity = '1';
            submitBtn.style.cursor = 'pointer';
            submitBtn.type = 'button';
            submitBtn.onclick = function(e) {
                e.preventDefault();
                lastScanStartTime = 0;
                fetch('/stop').then(r => r.text()).then(t => toast(t)).then(() => {
                    setTimeout(async () => {
                        const refreshedDiag = await fetch('/diag').then(r => r.text());
                        updateStatusIndicators(refreshedDiag);
                    }, 500);
                });
            };
        }

        if (detectionMethod === 'randomization-detection') {
          const randMode = document.getElementById('randomizationMode').value;
          fd.append('randomizationMode', randMode);
        }
        if (detectionMethod === 'drone-detection') {
          endpoint = '/drone';
          fd.delete('detection');
        }
        if (detectionMethod === 'counter-surveil') {
          endpoint = '/countersurveil';
          fd.delete('detection');
        }

        const resetState = () => {
          setTimeout(() => {
            state.inProgress = false;
          }, 500);
        };

        {
            const starterLabel = detMethodLabels[detectionMethod] || 'Scan';
            await prepScanStart(starterLabel + ' starting...\n');
        }

        if (detectionMethod === 'baseline') {
          setTimeout(updateBaselineStatus, 500);
          const rssiThreshold = document.getElementById('baselineRssiThreshold').value;
          const duration = document.getElementById('baselineDuration').value;
          const ramSize = document.getElementById('baselineRamSize').value;
          const sdMax = document.getElementById('baselineSdMax').value;
          const absence = document.getElementById('absenceThreshold').value;
          const reappear = document.getElementById('reappearanceWindow').value;
          const rssiDelta = document.getElementById('rssiChangeDelta').value;

          fetch('/baseline/config', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `rssiThreshold=${rssiThreshold}&baselineDuration=${duration}&ramCacheSize=${ramSize}&sdMaxDevices=${sdMax}&absenceThreshold=${absence}&reappearanceWindow=${reappear}&rssiChangeDelta=${rssiDelta}`
          }).then(() => {
            return fetch(endpoint, {
              method: 'POST',
              body: fd
            });
          }).then(r => {
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            toast(t, 'success');
            setTimeout(() => { tick(); }, 100);
            updateBaselineStatus();
          }).catch(err => {
            toast('Error: ' + err, 'error');
          }).finally(resetState);
        } else {
          fetch(endpoint, {
            method: 'POST',
            body: fd
          }).then(r => {
            if (r.status === 409) return r.text().then(t => { toast(t, 'warning'); return null; });
            return r.text();
          }).then(t => {
            if (t === null) return;
            toast(t, 'success');
            setTimeout(() => { tick(); }, 100);
          }).catch(err => {
            toast('Error: ' + err, 'error');
          }).finally(resetState);
        }
      });

      document.addEventListener('click', e => {
        const a = e.target.closest('a[href="/stop"]');
        if (!a) return;
        e.preventDefault();
        fetch('/stop').then(r => r.text()).then(t => toast(t));
      });

      document.addEventListener('click', e => {
        const a = e.target.closest('a[href="/mesh-test"]');
        if (!a) return;
        e.preventDefault();
        fetch('/mesh-test').then(r => r.text()).then(t => toast('Mesh test sent'));
      });
        
      // Mode status updates
      document.querySelector('#s select[name="mode"]')?.addEventListener('change', updateModeStatus);
      document.getElementById('randomizationMode')?.addEventListener('change', updateModeStatus);
      document.getElementById('deviceScanMode')?.addEventListener('change', updateModeStatus);
      document.getElementById('detectionMode')?.addEventListener('change', updateModeStatus);

      function showAutoEraseHelp() {
        toast('Auto-Erase: 1) Setup period prevents wipe during install 2) Vibration triggers countdown 3) You can cancel 4) Cooldown prevents false triggers', 'info');
      }

      // Battery Saver Functions
      async function enableBatterySaver() {
        const interval = document.getElementById('batterySaverInterval').value;
        try {
          const r = await fetch('/battery-saver?action=start&interval=' + interval);
          const t = await r.text();
          toast('Battery saver enabled with ' + interval + ' min heartbeat');
          updateBatterySaverStatus();
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function disableBatterySaver() {
        try {
          const r = await fetch('/battery-saver?action=stop');
          const t = await r.text();
          toast('Battery saver disabled');
          updateBatterySaverStatus();
        } catch(e) {
          toast('Error: ' + e.message);
        }
      }

      async function updateBatterySaverStatus() {
        try {
          const r = await fetch('/battery-saver?action=status');
          const data = await r.json();
          const el = document.getElementById('batterySaverStatus');
          if (data.enabled) {
            el.style.background = 'rgba(0,200,100,0.2)';
            el.style.color = 'var(--c-ok)';
            el.innerHTML = 'ACTIVE - Heartbeat every ' + data.interval + ' min | Next: ' + data.nextHeartbeat + 's';
          } else {
            el.style.background = 'rgba(0,0,0,0.2)';
            el.style.color = '#888';
            el.innerHTML = 'INACTIVE';
          }
        } catch(e) {}
      }

      function showBatterySaverHelp() {
        toast('Battery Saver: Disables WiFi/BLE scanning, reduces CPU to 80MHz, sends periodic heartbeats. Mesh UART stays active to receive commands like BATTERY_SAVER_STOP.', 'info');
      }

      // ---- Data Tab ----
      var dataRows=[],dataFiltered=[],dataCols=[],dataPage=0,dataSortCol=-1,dataSortAsc=false,dataSearchTimer=null;
      var DATA_PAGE_SIZE=50;
      var DATA_SETS={
        probedb:{url:'/api/probedb',clear:'/api/probedb/clear',fmt:'json',
          cols:['MAC','Vendor','RSSI','Sessions','Seen','First','Last','SSIDs','Rand'],
          keys:['mac','vendor','rssi','sessions','seen','first','last','ssids','rand']},
        probes:{url:'/api/probes.jsonl',clear:'/api/probes/clear',fmt:'jsonl',
          cols:['Time','MAC','RSSI','Ch','Count','Vendor','SSIDs','Rand','Hit'],
          keys:['t','mac','rssi','ch','cnt','v','ss','rand','hit']},
        deauth:{url:'/api/deauth.jsonl',clear:'/api/deauth/clear',fmt:'jsonl',
          cols:['Time','Src','Dst','BSSID','RSSI','Ch','Reason','Type'],
          keys:['t','src','dst','bssid','rssi','ch','reason','_type']},
        drones:{url:'/api/drones.jsonl',clear:'/api/drones/clear',fmt:'jsonl',
          cols:['Time','MAC','RSSI','UAV ID','Type','Lat','Lon'],
          keys:['timestamp','mac','rssi','uav_id','type','lat','lon']},
        vibrations:{url:'/api/vibrations.jsonl',clear:'/api/vibrations/clear',fmt:'jsonl',
          cols:['Time','Uptime','Lat','Lon'],
          keys:['t','uptime_ms','lat','lon']},
        baseline:{url:'/baseline/stats',clear:'/baseline/reset',fmt:'baseline',cols:[],keys:[]},
        syslog:{url:'/api/antihunter.log',clear:'/api/antihunter.log/clear',fmt:'text',
          cols:['Time','Message'],keys:['_time','_msg']},
        incidents:{url:'/api/incidents.jsonl',clear:'/api/incidents/clear',fmt:'jsonl',
          cols:['Uptime','Node','Src','Type','Raw'],
          keys:['ts','node','src','type','raw']}
      };
      let _saData=null;
      function refreshSentinelAnalysis(){ _saData=null; loadSentinelAnalysis(); }
      async function clearSentinelAnalysis(){
        if(!confirm('Clear all sentinel incidents (RAM + SD)?'))return;
        await fetch('/api/incidents',{method:'DELETE'}); _saData=null; loadSentinelAnalysis();
      }
      async function loadSentinelAnalysis(){
        const area=document.getElementById('saArea'); if(!area)return;
        if(!_saData){
          const r=await fetch('/api/incidents.jsonl');
          const t=r.ok?await r.text():'';
          _saData=t.split('\n').filter(x=>x.trim()).map(x=>{try{return JSON.parse(x)}catch(_){return null}}).filter(x=>x);
          const sel=document.getElementById('saType'); const cur=sel?sel.value:'ALL';
          const types=[...new Set(_saData.map(x=>x.type).filter(Boolean))].sort();
          if(sel){sel.innerHTML='<option value="ALL">All types</option>'+types.map(t=>`<option>${t}</option>`).join(''); sel.value=cur||'ALL';}
        }
        const ty=(document.getElementById('saType')||{}).value||'ALL';
        const q=((document.getElementById('saSearch')||{}).value||'').toLowerCase();
        let rows=_saData.filter(x=>(ty==='ALL'||x.type===ty)&&(!q||JSON.stringify(x).toLowerCase().includes(q)));
        const total=rows.length; rows=rows.slice(-300).reverse();
        // Per-type breakdown over the search-filtered set (ignores type filter so
        // you can see the whole distribution while drilled into one type).
        const base=_saData.filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q));
        const counts={}; base.forEach(x=>{const t=x.type||'?';counts[t]=(counts[t]||0)+1;});
        const SEVC={crit:'#fb7185',high:'#fb923c',med:'#facc15',info:'#38bdf8'};
        const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;');
        const fmtWhen=r=>{
          if(r.epoch&&r.epoch>946684800){
            const d=new Date(r.epoch*1000);
            return d.toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
          }
          const s=Math.floor((r.ts||0)/1000),h=Math.floor(s/3600),m=Math.floor(s%3600/60),ss=s%60;
          return (h?h+'h':'')+(m?m+'m':'')+ss+'s up';
        };
        const detailOf=r=>{
          let d=r.raw||'';
          if(r.type&&d.startsWith(r.type+':'))d=d.slice(r.type.length+1);
          if(r.src&&r.src!=='local'&&d.startsWith(r.src))d=d.slice(r.src.length).replace(/^:/,'');
          return d;
        };
        const breakdown=Object.keys(counts).sort((a,b)=>counts[b]-counts[a]).map(t=>{
          const sv=_saSev(t); const on=(ty===t);
          return `<span class="sa-chip" style="border-color:${SEVC[sv]};color:${on?'#fff':SEVC[sv]};background:${on?SEVC[sv]+'33':'transparent'};" onclick="(()=>{const s=document.getElementById('saType');if(s){s.value='${on?'ALL':t}';loadSentinelAnalysis();}})()">${esc(t.replace(/_/g,' '))}<span style="opacity:.6;margin-left:6px;">${counts[t]}</span></span>`;
        }).join('');
        const chipBar=`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;">${breakdown}</div>`;
        if(!rows.length){area.innerHTML=chipBar+'<div class="data-empty">No incidents.</div>';return;}
        const hasPeer=_saData.some(x=>x.src&&x.src!=='local');
        area.innerHTML=chipBar
          +`<div style="font-size:11px;color:var(--mut);margin-bottom:8px;">${total} incident${total!=1?'s':''}${ty!=='ALL'?' · '+ty:''}</div>`
          +'<div class="sa-wrap"><table class="sa-tbl"><thead><tr><th>Time</th><th>Sev</th><th>Type</th>'+(hasPeer?'<th>Source</th>':'')+'<th>Detail</th><th>Node</th></tr></thead><tbody>'
          +rows.map(r=>{const sv=_saSev(r.type||'');return `<tr><td class="sa-when">${esc(fmtWhen(r))}</td><td><span class="sa-pill sa-${sv}">${sv.toUpperCase()}</span></td><td class="sa-type" style="color:${_atkColor(r.type)};">${esc(r.type)}</td>`+(hasPeer?`<td class="sa-mac">${esc(r.src)}</td>`:'')+`<td class="sa-detail">${esc(detailOf(r))}</td><td><span class="sa-node">${esc(r.node)}</span></td></tr>`;}).join('')
          +'</tbody></table></div>';
      }
      // Prefix-based severity for sentinel incident types (mirrors detector card sev).
      function _saSev(t){
        t=(t||'').toUpperCase();
        if(/^(PMKID|SAE_DOS|KARMA|EAPOL_BAIT|KRACK|PMKID_FORGE|ATTACKER)/.test(t))return 'crit';
        if(/^(DEAUTH|BEACON|EVILTWIN|SSID_CONFUSION|PROBE_FLOOD|OWE_ABUSE|RID)/.test(t))return 'high';
        if(/^(FRAG|ASSOC_SLEEP)/.test(t))return 'med';
        return 'info';
      }
      function loadDataSet(){
        var ds=document.getElementById('dataSet').value;
        var cfg=DATA_SETS[ds];
        var area=document.getElementById('dataArea');
        area.innerHTML='<div class="data-empty">Loading...</div>';
        document.getElementById('dataPager').style.display='none';
        document.getElementById('dataSearch').value='';
        var exp=document.getElementById('dataExport');
        exp.href=cfg.url;
        exp.download=ds+(cfg.fmt==='text'?'.log':cfg.fmt==='json'?'.json':'.jsonl');
        document.getElementById('dataClear').style.display=cfg.clear?'':'none';
        fetch(cfg.url).then(function(r){
          if(!r.ok) throw new Error(r.status);
          return r.text();
        }).then(function(text){
          if(cfg.fmt==='baseline'){renderBaseline(text);return;}
          if(cfg.fmt==='text'){parseLogData(text,cfg);return;}
          if(cfg.fmt==='json'){dataRows=JSON.parse(text);}
          else{var lines=text.trim().split('\n');dataRows=[];for(var i=0;i<lines.length;i++){if(lines[i].trim()){try{dataRows.push(JSON.parse(lines[i]));}catch(e){}}}}
          dataCols=cfg.keys;dataPage=0;dataSortCol=-1;dataSortAsc=false;
          dataFiltered=dataRows.slice();
          var tk=dataCols.indexOf('last')>=0?'last':dataCols.indexOf('timestamp')>=0?'timestamp':dataCols.indexOf('t')>=0?'t':null;
          if(tk){var ci=dataCols.indexOf(tk);dataSortCol=ci;dataSortAsc=false;dataFiltered.sort(function(a,b){return(getVal(b,tk)||0)-(getVal(a,tk)||0);});}
          renderDataTable(cfg);
        }).catch(function(e){area.innerHTML='<div class="data-empty">No data available.</div>';});
      }
      function getVal(row,key){
        if(key==='_type') return row.disassoc?'DISASSOC':'DEAUTH';
        return row[key];
      }
      function fmtCell(val,key){
        if(val===undefined||val===null) return '-';
        if(key==='t'||key==='timestamp'||key==='first'||key==='last'){
          if(typeof val==='number'&&val>946684800) return new Date(val*1000).toISOString().replace('T',' ').substring(0,19)+' UTC';
          if(typeof val==='number'&&val>0){var s=val%60,m=Math.floor(val/60)%60,h=Math.floor(val/3600);return (h?h+'h ':'')+(m?m+'m ':'')+s+'s (uptime)';}
          if(typeof val==='number') return '-';
          return String(val);
        }
        if(key==='rssi'){var cls=val>-50?'rssi-good':val>-70?'rssi-mid':'rssi-bad';return '<span class="'+cls+'">'+val+' dBm</span>';}
        if(key==='rand') return val?'<span class="rand-yes">Yes</span>':'No';
        if(key==='hit'||key==='dst') return val?'<span style="color:var(--dang);font-weight:600">Yes</span>':'No';
        if(key==='ss'||key==='ssids'){
          if(Array.isArray(val)){if(val.length===0) return '-';var shown=val.slice(0,2).join(', ');if(val.length>2) shown+=' +'+(val.length-2)+' more';return shown;}
          return String(val);
        }
        if(key==='uptime_ms'){var s=Math.floor(val/1000);var m=Math.floor(s/60);s=s%60;var h=Math.floor(m/60);m=m%60;return (h?h+'h ':'')+(m?m+'m ':'')+(s+'s');}
        if(key==='mac'||key==='src'||key==='dst'||key==='bssid'){
          if(typeof privacyMode!=='undefined'&&privacyMode&&typeof val==='string'&&val.length>=17) return val.substring(0,9)+'XX:XX'+val.substring(14);
        }
        if(key==='_type') return val;
        return String(val);
      }
      function renderDataTable(cfg){
        var area=document.getElementById('dataArea');
        if(!dataFiltered.length){area.innerHTML='<div class="data-empty">No records found.</div>';document.getElementById('dataPager').style.display='none';return;}
        var start=dataPage*DATA_PAGE_SIZE,end=Math.min(start+DATA_PAGE_SIZE,dataFiltered.length);
        var html='<table id="data-table"><thead><tr>';
        for(var c=0;c<cfg.cols.length;c++){
          var arrow='';if(dataSortCol===c) arrow='<span class="sort-arrow">'+(dataSortAsc?'&#9650;':'&#9660;')+'</span>';
          html+='<th onclick="sortDataCol('+c+')">'+cfg.cols[c]+arrow+'</th>';
        }
        html+='</tr></thead><tbody>';
        for(var i=start;i<end;i++){html+='<tr>';for(var c=0;c<dataCols.length;c++){html+='<td>'+fmtCell(getVal(dataFiltered[i],dataCols[c]),dataCols[c])+'</td>';}html+='</tr>';}
        html+='</tbody></table>';area.innerHTML=html;
        var pager=document.getElementById('dataPager');
        if(dataFiltered.length>DATA_PAGE_SIZE){
          pager.style.display='flex';
          document.getElementById('dataPageInfo').textContent=(start+1)+'-'+end+' of '+dataFiltered.length;
          document.getElementById('dataPrevBtn').disabled=dataPage===0;
          document.getElementById('dataNextBtn').disabled=end>=dataFiltered.length;
        } else { pager.style.display='none'; }
      }
      function sortDataCol(ci){
        var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
        if(dataSortCol===ci){dataSortAsc=!dataSortAsc;}else{dataSortCol=ci;dataSortAsc=true;}
        var key=dataCols[ci];
        dataFiltered.sort(function(a,b){
          var av=getVal(a,key),bv=getVal(b,key);
          if(av===undefined||av===null) av='';if(bv===undefined||bv===null) bv='';
          if(typeof av==='number'&&typeof bv==='number') return dataSortAsc?av-bv:bv-av;
          av=String(av).toLowerCase();bv=String(bv).toLowerCase();
          return dataSortAsc?av.localeCompare(bv):bv.localeCompare(av);
        });
        dataPage=0;renderDataTable(cfg);
      }
      function onDataSearch(){
        clearTimeout(dataSearchTimer);
        dataSearchTimer=setTimeout(function(){
          var q=document.getElementById('dataSearch').value.toLowerCase();
          var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
          if(!q){dataFiltered=dataRows.slice();}else{
            dataFiltered=dataRows.filter(function(row){
              for(var c=0;c<dataCols.length;c++){var v=getVal(row,dataCols[c]);if(v!==undefined&&v!==null&&String(v).toLowerCase().indexOf(q)>=0) return true;}
              return false;
            });
          }
          dataPage=0;renderDataTable(cfg);
        },300);
      }
      function dataPagePrev(){if(dataPage>0){dataPage--;renderDataTable(DATA_SETS[document.getElementById('dataSet').value]);}}
      function dataPageNext(){var ds=document.getElementById('dataSet').value;if((dataPage+1)*DATA_PAGE_SIZE<dataFiltered.length){dataPage++;renderDataTable(DATA_SETS[ds]);}}
      function clearDataSet(){
        var ds=document.getElementById('dataSet').value,cfg=DATA_SETS[ds];
        if(!cfg.clear) return;
        if(!confirm('Clear all '+ds+' data? This cannot be undone.')) return;
        fetch(cfg.clear,{method:'POST'}).then(function(r){if(r.ok){toast('Data cleared','success');loadDataSet();}else toast('Clear failed','error');});
      }
      function parseLogData(text,cfg){
        dataRows=[];dataCols=cfg.keys;
        var lines=text.trim().split('\n');
        for(var i=0;i<lines.length;i++){var line=lines[i];var m=line.match(/^\[([^\]]+)\]\s*(.*)$/);if(m){dataRows.push({_time:m[1],_msg:m[2]});}else if(line.trim()){dataRows.push({_time:'',_msg:line});}}
        dataRows.reverse();dataFiltered=dataRows.slice();dataPage=0;dataSortCol=-1;dataSortAsc=false;renderDataTable(cfg);
      }
      function renderBaseline(text){
        var area=document.getElementById('dataArea');document.getElementById('dataPager').style.display='none';
        try{var d=JSON.parse(text);
          area.innerHTML='<div class="stat-grid">'
            +'<div class="stat-item"><div class="stat-label">Devices</div><div class="stat-value">'+(d.deviceCount||d.devices||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">RAM Cache</div><div class="stat-value">'+(d.ramSize||d.ram||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">SD Cache</div><div class="stat-value">'+(d.sdSize||d.sd||0)+'</div></div>'
            +'<div class="stat-item"><div class="stat-label">RSSI Threshold</div><div class="stat-value">'+(d.rssiThreshold||d.rssi||'-70')+' dBm</div></div>'
            +'<div class="stat-item"><div class="stat-label">Absence</div><div class="stat-value">'+(d.absenceThreshold||d.absence||'120')+'s</div></div>'
            +'<div class="stat-item"><div class="stat-label">Reappear Window</div><div class="stat-value">'+(d.reappearWindow||d.reappear||'300')+'s</div></div>'
            +'</div><div style="margin-top:16px;"><button class="btn danger" onclick="if(confirm(\'Reset all baseline data?\'))fetch(\'/baseline/reset\',{method:\'POST\'}).then(function(){toast(\'Baseline reset\',\'success\');loadDataSet();})">Reset Baseline</button></div>';
        }catch(e){area.innerHTML='<div class="data-empty">No baseline data available.</div>';}
      }

      // Initialize
      refreshIdentityMap(true);
      load();
      updatePrivacyBtn();
      setInterval(() => { if (pageActive('system')) updateBatterySaverStatus(); }, 5000);
      loadBaselineAnomalyConfig();
      loadMeshInterval();
      loadDedupTtl();
      updateAutoEraseStatus();
      refreshPskStatus();
      pollSecureState();
      setInterval(tick, 5000);
      setInterval(() => { const a = document.getElementById('diagAge'); if (!a || !window.__lastDiag) return; const s = Math.max(0, Math.round((Date.now() - window.__lastDiag) / 1000)); a.innerText = s < 1 ? 'refreshed just now' : 'refreshed ' + s + 's ago'; }, 1000);
      document.getElementById('detectionMode').dispatchEvent(new Event('change'));

      // ===== Detect tab logic =====
      function _safeParse(s){
        try{return JSON.parse(s);}
        catch(e){console.warn('detect: bad json line', e); return null;}
      }
      async function _jt(u){
        try{const r=await fetch(u);if(!r.ok)return '';return await r.text();}
        catch(e){console.warn('detect: fetch text failed', u, e); return '';}
      }
      async function _jj(u){
        try{const r=await fetch(u);return await r.json();}
        catch(e){console.warn('detect: fetch json failed', u, e); return null;}
      }
      function _countLines(s){if(!s)return 0;return s.split('\n').filter(l=>l.trim()).length}
      const GROUPS={
        dos:[['DEAUTH_FORGE','Deauth Forge',null],['DEAUTH_FLOOD','Deauth Flood',null],
          ['BEACON_FLOOD','Beacon Flood','eviltwin'],['AUTH_FLOOD','Auth Flood',null],
          ['ASSOC_SLEEP','Assoc Sleep','assoc_sleep'],['SAE_DOS','SAE DoS','sae'],
          ['DEAUTH_AP_TARGETED','AP Deauth (event)',null]],
        rogue:[['EVILTWIN','Evil Twin','eviltwin'],['OWE_ABUSE','OWE Abuse','owe'],
          [['KARMA_CAND','KARMA_CONFIRMED'],'Karma','karma']],
        recon:[[['PMKID_HARVEST','PMKID_FORGE'],'PMKID Harvest','pmkid'],
          ['PROBE_FLOOD','Probe Flood','probe_flood'],['HSHK','Handshake Capture','hshk']],
        physical:[['FRAG','FragAttacks','frag'],['TSF','TSF / Evil-Twin','tsf'],['JAM','WiFi Interf (L2)','jam']],
        mesh:[['MESH_SPOOF_SELF','Self-Spoof','mesh_guard'],['MESH_FLOOD','Channel Flood','mesh_guard']]
        /* BLE attack group display disabled per user 2026-05-23 (BLE scan path unreliable on this build)
        ,ble:[['BLE_ATTACK','BLE Attack Tools','ble_attack'],['BLE_MALFORMED','BLE Malformed','ble_malformed'],['BLETRACK','Tracker','tracker'],['AIRTAG','AirTag','airtag']]
        */
      };
      function _grpRows(dets,inc,cfg,nowMs){
        const ago=t=>{if(!t)return '--';const s=Math.floor((nowMs-t)/1000);if(s<1)return 'now';if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h';};
        let h='<div class="drow-head"><span></span><span>Detector</span><span class="rh-r">Hits</span><span class="rh-r">Last</span><span class="rh-r">On</span></div>';
        dets.forEach(d=>{
          const types=Array.isArray(d[0])?d[0]:[d[0]];
          const hits=inc.filter(x=>x&&types.includes(x.type));
          const cnt=hits.length;
          const last=cnt?Math.max(...hits.map(x=>x.ts||0)):0;
          const key=d[2];
          const on=key?(cfg[key]===true):true;
          const fire=cnt>0;
          const ctrl=key
            ?`<label class="dsw"><input type="checkbox" ${on?'checked':''} onchange="detPostCfg({${key}:this.checked});"><span class="dsw-s"></span></label>`
            :`<span class="don-pill" title="Always on">ON</span>`;
          h+=`<div class="drow${on?' on':''}${fire?' fire':''}">`
            +`<span class="drow-dot"></span>`
            +`<span class="drow-name">${d[1]}</span>`
            +`<span class="drow-hits${fire?' hot':''}">${cnt}</span>`
            +`<span class="drow-last">${ago(last)}</span>`
            +`<span class="drow-ctrl">${ctrl}</span></div>`;
        });
        return h;
      }
      function _dosSyncMode(scan){
        const d=document.getElementById('dos-mode-defend'), s=document.getElementById('dos-mode-scan'),
              t=document.getElementById('dos-mode-desc');
        if(d)d.className=scan?'btn alt':'btn primary';
        if(s)s.className=scan?'btn primary':'btn alt';
        if(t)t.textContent=scan?'Hopping all channels — sees attacks on set WiFi channels (AP clients may drop).'
                               :'Locked to this AP’s channel — catches attacks against us. (Stable)';
      }
      async function detScanMode(scan){
        _dosSyncMode(scan);
        await detPostCfg({sentinel_scan:scan});
        if(_detCfg)_detCfg.sentinel_scan=scan;
      }
      function _grpChipState(cfg){
        if(typeof DET_GROUPS==='undefined')return;
        for(const g in DET_GROUPS){
          const c=document.getElementById('grpchip-'+g);
          if(c)c.className=DET_GROUPS[g].some(k=>(cfg||{})[k])?'btn primary':'btn alt';
        }
      }
      async function renderDos(){
        const inc=await _jj('/api/incidents.json?limit=200')||[];
        const cfg=_detCfg||{};
        _dosSyncMode(!!cfg.sentinel_scan);
        const nowMs=inc.reduce((m,x)=>Math.max(m,(x&&x.ts)||0),0);
        for(const gid in GROUPS){
          const el=document.getElementById(gid+'-rows');
          if(el)el.innerHTML=_grpRows(GROUPS[gid],inc,cfg,nowMs);
        }
        const GLBL={dos:'DoS',rogue:'Rogue AP',recon:'Recon',physical:'Physical',mesh:'Mesh',ble:'BLE'};
        let qv='';
        for(const gid in GROUPS){
          const dets=GROUPS[gid]; let en=0,ht=0;
          dets.forEach(d=>{
            if(d[2]?(cfg[d[2]]===true):true)en++;
            const types=Array.isArray(d[0])?d[0]:[d[0]];
            ht+=inc.filter(x=>x&&types.includes(x.type)).length;
          });
          const hot=ht>0?'border-color:var(--bad,#e55);':'';
          qv+=`<div style="border:1px solid var(--bord);border-radius:6px;padding:6px 8px;${hot}">`
            +`<div style="font-size:11px;color:var(--mut);">${GLBL[gid]||gid}</div>`
            +`<div style="font-size:13px;"><b>${en}/${dets.length}</b> on · <span style="${ht>0?'color:var(--bad,#e55);font-weight:700;':''}">${ht} hit${ht!=1?'s':''}</span></div></div>`;
        }
        const qe=document.getElementById('dctl-quick'); if(qe)qe.innerHTML=qv;
        _grpChipState(cfg);
        const setc=(id,types)=>{const e=document.getElementById(id);if(e)e.textContent=inc.filter(x=>x&&types.includes(x.type)).length;};
        setc('d-karma',['KARMA_CAND','KARMA_CONFIRMED']);
        setc('d-authflood',['AUTH_FLOOD']);
        setc('d-beaconflood',['BEACON_FLOOD']);
        setc('d-dauth',['DEAUTH_FLOOD','DEAUTH_FORGE','DEAUTH_AP_TARGETED']);
        setc('d-pmkid',['PMKID_HARVEST','PMKID_FORGE']);
        setc('d-et',['EVILTWIN']);
        setc('d-sc',['SSID_CONFUSION']);
        setc('d-sae',['SAE_DOS']);
        setc('d-owe',['OWE_ABUSE']);
        setc('d-frag',['FRAG']);
        setc('d-asl',['ASSOC_SLEEP']);
        setc('d-pfl',['PROBE_FLOOD','PROBE_FLOOD_BEHAVE','PROBE_FLOOD_AP']);
        setc('d-tsf',['TSF']);
        setc('d-jam',['JAM']);
        setc('d-mgd',['MESH_SPOOF_SELF','MESH_FLOOD']);
        setc('d-pwna',['PWNAGOTCHI']);
        setc('d-rid-ov',['RID']);
        _overviewVisibility(cfg);
      }
      // Hide overview stats whose detector is disabled AND has zero hits.
      // 'always' stats and any stat with a non-zero count stay visible.
      function _overviewVisibility(cfg){
        cfg=cfg||_detCfg||{};
        document.querySelectorAll('#detOverviewCardBody .stat[data-cfg]').forEach(el=>{
          const keys=el.dataset.cfg;
          const ve=el.querySelector('.stat-value');
          const cnt=ve?(parseInt(ve.textContent,10)||0):0;
          const enabled=keys==='always'||keys.split(',').some(k=>cfg[k]===true);
          el.style.display=(enabled||cnt>0)?'':'none';
        });
      }
      async function detectTick(){
        const tab=document.getElementById('page-detect');
        if(!tab||!tab.classList.contains('active'))return;
        const [pm,et,sc,sa,ow,fr,bm,df,q,b,p,rid,tr,rc,ch]=await Promise.all([
          _jt('/api/pmkid.jsonl'),_jt('/api/eviltwin.jsonl'),
          _jt('/api/ssid_confusion.jsonl'),_jt('/api/sae_dos.jsonl'),
          _jt('/api/owe_abuse.jsonl'),_jt('/api/fragattack.jsonl'),
          _jt('/api/ble_malformed.jsonl'),_jt('/api/deauth_flood.jsonl'),
          _jj('/api/quorum'),_jj('/api/bloom'),_jj('/api/pps'),
          _jj('/api/rid_claims'),_jj('/api/ble_tracker'),_jj('/api/recon'),
          _jj('/api/channel_partition')
        ]);
        const dEl = document.getElementById('d-dauth');
        if (dEl) dEl.textContent = _countLines(df);
        document.getElementById('d-pmkid').textContent=_countLines(pm);
        document.getElementById('d-et').textContent=_countLines(et);
        document.getElementById('d-sc').textContent=_countLines(sc);
        document.getElementById('d-sae').textContent=_countLines(sa);
        document.getElementById('d-owe').textContent=_countLines(ow);
        document.getElementById('d-frag').textContent=_countLines(fr);
        document.getElementById('d-rec').textContent=(rc||[]).length;
        document.getElementById('d-pps').textContent=p?(p.locked?'YES':'no')+' edge='+p.last_edge:'--';
        document.getElementById('d-bl').textContent=b?(b.local_bits_set+' / '+b.capacity_bits):'--';
        document.getElementById('d-bn').textContent=b?(b.neighbor_bits_set+' / '+b.capacity_bits):'--';
        document.getElementById('d-qc').textContent=q?((q.candidates||[]).length):0;
        document.getElementById('d-quorum').textContent=q?JSON.stringify(q,null,2):'--';
        document.getElementById('d-chan').textContent=ch?JSON.stringify(ch,null,2):'--';
        {const _e=document.getElementById('d-rid');if(_e)_e.textContent=rid?JSON.stringify(rid,null,2):'[]';}
        detRenderTable('d-recpre',rc||[],[
          {key:'id',label:'TrackId'},{key:'score',label:'Score'},
          {key:'reasons',label:'Reasons'},{key:'ts',label:'Last',get:r=>_ago(r.ts)}
        ]);
        const evtRows=[];
        function parseLines(s,kind,sevHint){
          (s||'').split('\n').filter(l=>l.trim()).forEach(l=>{
            const o=_safeParse(l);
            if(o)evtRows.push({kind,sev:sevHint,ts:o.ts||0,raw:l,o});
          });
        }
        parseLines(pm,'PMKID','crit');parseLines(et,'EvilTwin','high');parseLines(sc,'SSIDConf','high');
        parseLines(sa,'SAE','high');parseLines(ow,'OWE','med');parseLines(fr,'Frag','med');
        parseLines(bm,'BLEMalformed','med');
        evtRows.sort((a,b)=>(b.ts||0)-(a.ts||0));
        detRenderTable('d-stream',evtRows.slice(0,40),[
          {key:'kind',label:'Type'},
          {key:'sev',label:'Sev',get:r=>r.sev.toUpperCase()},
          {key:'ts',label:'Age',get:r=>_ago(r.ts)},
          {key:'raw',label:'Detail',get:r=>r.raw}
        ]);
        if((rc||[]).length>0)detMarkActive('recon');
        if(_countLines(pm)>0||_countLines(et)>0||_countLines(sc)>0||_countLines(sa)>0)detMarkActive('rid');
        renderDos();
      }
      async function detectClearAll(){await fetch('/api/detect/clear_all',{method:'POST'});detectTick()}
      async function pgTick(){
        if(!detTabActive())return;
        const pg=await _jj('/api/probegraph');
        const n=(pg||[]).length;
        {const _e=document.getElementById('pg-n');if(_e)_e.textContent=n;}
        detRenderTable('pg-pre',pg||[],[
          {key:'hash',label:'Hash'},{key:'local',label:'TrackId'},
          {key:'best_rssi',label:'Best RSSI'},{key:'sightings',label:'Sight'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(n>0)detMarkActive('probegraph');
      }
      async function pgClear(){await fetch('/api/probegraph/clear',{method:'POST'});pgTick();}
      async function hsTick(){
        if(!detTabActive())return;
        const [r,s]=await Promise.all([_jj('/api/handshakes'),_jj('/api/handshakes/stats')]);
        if(s){
          {const _e=document.getElementById('hs-n');if(_e)_e.textContent=s.count;}
          const ko=document.getElementById('d-hs-krack'); if(ko)ko.textContent=s.krack_events||0;
        }
        const rows=(r||[]).map(x=>Object.assign({mask:['','M1','M2','M3','M4','M1M2','M1M3','M1-3','M4o','M1M4','M2M4','M1-3M4','M3M4','M1M3M4','M2-4','M1-4'][x.seen_mask&15]||x.seen_mask},x));
        detRenderTable('hs-pre',rows,[
          {key:'bssid',label:'BSSID'},{key:'sta',label:'STA'},
          {key:'mask',label:'Msgs'},{key:'complete',label:'Done'},
          {key:'krack_events',label:'KRACK'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(s&&s.krack_events>0)detMarkActive('handshake');
      }
      async function hsClear(){await fetch('/api/handshakes/clear',{method:'POST'});hsTick();}
      async function ahTick(){
        if(!detTabActive())return;
        const h=await _jj('/api/attacker_hunts');
        const n=(h||[]).length;
        {const _e=document.getElementById('ah-n');if(_e)_e.textContent=n;}
        const o=document.getElementById('d-ah-n'); if(o)o.textContent=n;
        detRenderTable('ah-pre',h||[],[
          {key:'mac',label:'MAC'},{key:'type',label:'Type'},
          {key:'started',label:'Started',get:r=>_ago(r.started)},
          {key:'last_kick',label:'Last Kick',get:r=>_ago(r.last_kick)}
        ]);
        if(n>0)detMarkActive('hunts');
      }
      async function ahClear(){await fetch('/api/attacker_hunts/clear',{method:'POST'});ahTick();}
      async function kmTick(){
        if(!detTabActive())return;
        const [s,c]=await Promise.all([_jj('/api/karma/stats'),_jj('/api/karma')]);
        if(s){document.getElementById('km-on').textContent=s.enabled?'YES':'no';
              document.getElementById('km-c').textContent=s.candidates;
              document.getElementById('km-x').textContent=s.confirmed;}
        detRenderTable('km-pre',c||[],[
          {key:'bssid',label:'BSSID'},{key:'distinct_ssids',label:'SSIDs'},
          {key:'bait_emitted',label:'Bait'},{key:'confirmed',label:'Confirmed'},
          {key:'last_ssid',label:'Last SSID'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(s&&s.confirmed>0)detMarkActive('karma');
      }
      async function kmToggle(on){const fd=new FormData();fd.append('on',on);await fetch('/api/karma/enable',{method:'POST',body:fd});kmTick();}
      async function kmClear(){await fetch('/api/karma/clear',{method:'POST'});kmTick();}
      async function tsfTick(){
        if(!detTabActive())return;
        const t=await _jj('/api/tsf_skew');
        {const _e=document.getElementById('tsf-n');if(_e)_e.textContent=(t||[]).length;}
        detRenderTable('tsf-pre',t||[],[
          {key:'bssid',label:'BSSID'},{key:'ssid',label:'SSID'},
          {key:'chan_a',label:'Ch A'},{key:'chan_b',label:'Ch B'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
      }
      async function tsfClear(){await fetch('/api/tsf_skew/clear',{method:'POST'});tsfTick();}
      async function jammingTick(){
        if(!detTabActive())return;
        const a=await _jsonl('/api/jamming.jsonl');
        document.getElementById('jam-n').textContent=a.length;
        _renderJsonl('jam-pre',a,['ts','ch','pdr','err','valid','err_rssi']);
        if(a.length>0)detMarkActive('jamming');
      }
      async function jamClear(){await fetch('/api/jamming/clear',{method:'POST'});jammingTick();}
      async function meshGuardTick(){
        if(!detTabActive())return;
        const a=await _jsonl('/api/meshguard.jsonl');
        document.getElementById('mgd-n').textContent=a.length;
        _renderJsonl('mgd-pre',a,['ts','evt']);
        if(a.length>0)detMarkActive('meshguard');
      }
      async function mgdClear(){await fetch('/api/meshguard/clear',{method:'POST'});meshGuardTick();}
      async function trkTick(){
        if(!detTabActive())return;
        const [chains,watch]=await Promise.all([_jj('/api/tracker_chains'),_jj('/api/ble_tracker')]);
        const n=(chains||[]).length;
        document.getElementById('trk-n').textContent=n;
        detRenderTable('trk-pre',chains||[],[
          {key:'chain',label:'Chain'},{key:'vendor',label:'Vendor'},
          {key:'links',label:'Links'},{key:'avg_rssi',label:'Avg RSSI'},
          {key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        detRenderTable('d-trkpre',watch||[],[
          {key:'addr',label:'Addr'},{key:'vendor',label:'Vendor'},
          {key:'sightings',label:'Sight'},{key:'avg_rssi',label:'RSSI'},
          {key:'score',label:'Score'},{key:'last_seen',label:'Last',get:r=>_ago(r.last_seen)}
        ]);
        if(n>0||(watch||[]).length>0)detMarkActive('trackers');
      }
      async function trkClear(){await fetch('/api/tracker_chains/clear',{method:'POST'});trkTick();}
      async function atTick(){
        if(!detTabActive())return;
        const a=await _jj('/api/airtag_presence');
        const n=(a||[]).length;
        document.getElementById('at-n').textContent=n;
        detRenderTable('at-pre',a||[],[
          {key:'addr',label:'Addr'},{key:'owner_nearby',label:'Owner'},
          {key:'battery',label:'Battery'},{key:'observations',label:'Obs'},
          {key:'last_rssi',label:'RSSI'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
        if(n>0)detMarkActive('airtag');
      }
      async function atClear(){await fetch('/api/airtag_presence/clear',{method:'POST'});atTick();}
      async function baTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/ble_attack.jsonl');
        document.getElementById('ba-n').textContent=a.length;
        _renderJsonl('ba-pre',a,['ts','tool','addr','family','rssi','reason']);
        if(a.length>0)detMarkActive('bleattack');
      }
      async function baClear(){await fetch('/api/ble_attack/clear',{method:'POST'});baTick();}
      async function detectClearTrackers(){await fetch('/api/ble_tracker/clear',{method:'POST'});detectTick()}
      async function tofTick(){
        if(!detTabActive())return;
        const t=await _jj('/api/tof');
        {const _e=document.getElementById('tof-n');if(_e)_e.textContent=(t||[]).length;}
        detRenderTable('tof-pre',t||[],[
          {key:'node',label:'Node'},{key:'last_rtt_us',label:'Last RTT us'},
          {key:'best_rtt_us',label:'Best us'},{key:'avg_rtt_us',label:'Avg us'},
          {key:'samples',label:'N'},{key:'last',label:'Last',get:r=>_ago(r.last)}
        ]);
      }
      async function tofPing(){
        const tgt=document.getElementById('tof-target-in').value||'*';
        const fd=new FormData();fd.append('target',tgt);
        await fetch('/api/tof/ping',{method:'POST',body:fd});tofTick();
      }
      async function tofClear(){await fetch('/api/tof/clear',{method:'POST'});tofTick();}
      const _detLastActivity={};
      let _detSev='all';
      function detApplyFilters(){
        const q=(document.getElementById('det-filter').value||'').toLowerCase().trim();
        document.querySelectorAll('#page-detect .card').forEach(c=>{
          const h=c.querySelector('.card-header h3');
          const t=h?h.textContent.toLowerCase():'';
          const sev=c.dataset.sev||'';
          const key=c.dataset.key||'';
          let show=true;
          if(q && !t.includes(q)) show=false;
          if(_detSev==='crit'&&sev!=='crit') show=false;
          else if(_detSev==='high'&&!(sev==='crit'||sev==='high')) show=false;
          else if(_detSev==='med'&&!(sev==='crit'||sev==='high'||sev==='med')) show=false;
          else if(_detSev==='info'&&sev!=='info') show=false;
          else if(_detSev==='firing'&&!_detLastActivity[key]) show=false;
          c.classList.toggle('hidden', !show);
        });
        detSortByActivity();
      }
      function detSortByActivity(){
        const parent=document.getElementById('page-detect');
        if(!parent)return;
        const cards=[...parent.querySelectorAll('.card[data-key]')];
        cards.sort((a,b)=>{
          const aa=_detLastActivity[a.dataset.key]||0;
          const bb=_detLastActivity[b.dataset.key]||0;
          return bb-aa;
        });
        cards.forEach(c=>parent.appendChild(c));
      }
      const _detPageLoadMs = Date.now();

      let _sentToggleBusy=false;
      async function sentinelToggleHdr(){
        if(_sentToggleBusy) return;
        _sentToggleBusy=true;
        try {
          const sr = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!sr.ok) return;
          const s = await sr.json();
          const url = s.enabled ? '/api/sentinel/stop' : '/api/sentinel/start';
          const rr = await fetch(url, {method:'POST',cache:'no-store'});
          if (!rr.ok) alert('Sentinel toggle failed: ' + await rr.text());
          await new Promise(r=>setTimeout(r,500));
          await sentinelHdrRefresh();
          if (typeof sentinelRefresh==='function') await sentinelRefresh();
        } catch (err) {
          console.warn('sentinelToggleHdr failed', err);
        } finally { _sentToggleBusy=false; }
      }
      async function sentinelHdrRefresh(){
        try {
          const r = await fetch('/api/sentinel/status',{cache:'no-store'});
          if (!r.ok) return;
          const s = await r.json();
          const el = document.getElementById('sentStatusHdr');
          if (!el) return;
          if (!s.enabled) {
            el.style.display = 'none';
          } else if (s.scanning) {
            el.style.display = '';
            el.textContent = 'SENTINEL PAUSED (SCAN)';
            el.style.color = '#fca5a5';
            el.style.borderColor = '#dc2626';
          } else if (s.running) {
            el.style.display = '';
            el.textContent = 'SENTINEL ON';
            el.style.color = '#86efac';
            el.style.borderColor = '#16a34a';
          } else {
            el.style.display = '';
            el.textContent = 'SENTINEL IDLE';
            el.style.color = '';
            el.style.borderColor = '';
          }
        } catch (err) {
          console.warn('sentinelHdrRefresh failed', err);
        }
      }
      async function sentinelSetBoot(on){
        try{
          await fetch('/api/sentinel/boot',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'on='+(on?1:0)});
          toast(on?'Sentinel will auto-start on boot':'Boot auto-start disabled');
        }catch(err){ console.warn('sentinelSetBoot failed', err); toast('Failed to set boot state','warning'); }
      }
      async function sentinelBootRefresh(){
        try{
          const r=await fetch('/api/sentinel/boot',{cache:'no-store'});
          if(r.ok){const j=await r.json();const c=document.getElementById('sentBootChk');if(c)c.checked=!!j.boot;}
        }catch(err){ console.warn('sentinelBootRefresh failed', err); }
      }
      setInterval(()=>{sentinelHdrRefresh(); if(pageActive('detect') && typeof sentinelRefresh==='function')sentinelRefresh();}, 4000);
      setTimeout(sentinelHdrRefresh, 700);
      setTimeout(sentinelBootRefresh, 800);
      function detMarkActive(key){
        _detLastActivity[key]=Date.now();
        if (Date.now() - _detPageLoadMs < 10000) return;
        const card=document.querySelector('#page-detect .card[data-key="'+key+'"]');
        if(card){const sev=card.dataset.sev||'';if(sev==='crit'||sev==='high')detPushAlert(key,card);}
      }

      const VERIFIED_DETECTORS = new Set(['events','sentinel','overview','mesh','pmkid','eviltwin']);
      const DETECTOR_TOGGLE_KEYS = {
        'pmkid':'pmkidOn','eviltwin':'etwOn','ssidconf':'scnOn','saedos':'saeOn',
        'oweabuse':'oweOn','frag':'fragOn','karma':'karmaOn',
        'pwna':'pwnaOn','tsf':'tsfOn','jamming':'jamOn','meshguard':'mgdOn',
        'trackers':'trkOn','airtag':'atgOn','bleattack':'blatkOn','blemal':'blemOn',
        'rid':'ridOn','probeflood':'pflOn','assocsleep':'aslOn',
        'pmkidforge':'pmkidOn','beaconforge':'etwOn','eapolbait':'pmkidOn',
        'handshake':'hshkOn','krack':'krackOn','hunts':'trlOn'
      };
      let _detToggleState = {};
      async function detRefreshToggleState(){
        try {
          const r = await fetch('/api/detect/config');
          if (!r.ok) return;
          _detToggleState = await r.json();
          detApplyStatusPills();
        } catch (fetchErr) {
          console.warn('detRefreshToggleState failed', fetchErr);
        }
      }
      function detApplyStatusPills(){
        document.querySelectorAll('#page-detect .card[data-key] .dpill').forEach(p=>p.remove());
      }
      setInterval(() => { if (pageActive('detect')) detRefreshToggleState(); }, 10000);
      setTimeout(detRefreshToggleState, 600);
      const _detAlerts=[];
      function detPushAlert(key,card){
        const title=card.querySelector('.card-header h3');
        let txt=key;
        if(title){
          const clone=title.cloneNode(true);
          clone.querySelectorAll('.sev,.num,.dpill').forEach(n=>n.remove());
          txt=clone.textContent.replace(/\\s+/g,' ').trim();
          if(!txt)txt=key;
        }
        const toggleKey=DETECTOR_TOGGLE_KEYS[key];
        if(toggleKey){
          if(!_detToggleState || Object.keys(_detToggleState).length===0)return;
          if(_detToggleState[toggleKey]!==true)return;
        }
        const sev=card.dataset.sev||'med';
        const exists=_detAlerts.find(a=>a.key===key);
        if(exists){exists.ts=Date.now();return;}
        _detAlerts.unshift({key,txt,sev,ts:Date.now()});
        while(_detAlerts.length>5)_detAlerts.pop();
        detRenderBanner();
      }
      function detRenderBanner(){
        const b=document.getElementById('det-banner');const bd=document.getElementById('det-banner-body');
        if(!b||!bd)return;
        if(_detAlerts.length===0){b.classList.remove('show');bd.innerHTML='';return;}
        const now=Date.now();
        const fresh=_detAlerts.filter(a=>now-a.ts<300000).slice(0,3);
        if(fresh.length===0){b.classList.remove('show');return;}
        b.classList.add('show');
        bd.innerHTML = fresh.map(a => {
          const secs = Math.floor((now - a.ts) / 1000);
          const when = secs < 60 ? `${secs}s ago` : `${Math.floor(secs / 60)}m ago`;
          const escapedKey = a.key.replace(/'/g, "\\'");
          
          return `<div class="bn-row" onclick="detJump('${escapedKey}')">` +
          `<span class="sev ${a.sev}" style="margin-right:6px;">${a.sev}</span>` +
          `<span class="bn-when" style="margin-right:8px;">${when}</span>` +
          `<span class="bn-msg">${a.txt}</span></div>`;
        }).join('');
      }
      setInterval(()=>{ if(pageActive('detect')) detRenderBanner(); },5000);

      const DETECTOR_TAB_MAP = {
        'events':'live','sentinel':'live','mesh':'config','config':'config',
        'overview':'live','apclients':'live',
        'dctl':'detectors','dos':'detectors','rogue':'detectors','recongrp':'detectors',
        'physical':'detectors','meshcfg':'detectors','mesh':'detectors',
        'analysis':'analysis'
      };

      function _detCardTab(c){
        const key=c.dataset.key||'';
        let cardTab=DETECTOR_TAB_MAP[key];
        if(!cardTab){
          const txt=(c.querySelector('h3')?.textContent||'').toLowerCase();
          if(txt.includes('detector controls')||txt.includes('threshold'))cardTab='config';
          else if(txt.includes('overview'))cardTab='live';
          else if(txt.includes('mesh defense'))cardTab='config';
          else if(c.dataset.sev&&key!=='events')cardTab='details';
          else cardTab='detectors';
        }
        return cardTab;
      }
      function detSetTab(tab){
        document.querySelectorAll('#det-tabs button.dtab').forEach(b=>{
          b.classList.toggle('active', b.dataset.dtab===tab);
        });
        document.querySelectorAll('#page-detect .card').forEach(c=>{
          c.classList.toggle('dtab-hidden', _detCardTab(c)!==tab);
        });
        document.querySelectorAll('[data-dtab-target]').forEach(el=>{
          const allowed=el.dataset.dtabTarget.split(',');
          el.classList.toggle('dtab-hidden', !allowed.includes(tab));
        });
        if(tab==='analysis'&&typeof loadSentinelAnalysis==='function') setTimeout(loadSentinelAnalysis,40);
        if (window.localStorage) {
          try {
            localStorage.setItem('detTab', tab);
          } catch (storageErr) {
            console.warn('detSetTab: localStorage write failed (private mode?)', storageErr);
          }
        }
      }
      function detTabRestore(){
        let saved = 'live';
        if (window.localStorage) {
          try {
            saved = localStorage.getItem('detTab') || 'live';
          } catch (storageErr) {
            console.warn('detSetTab: localStorage read failed (private mode?)', storageErr);
          }
        }
        if (saved !== 'live' && saved !== 'detectors' && saved !== 'analysis') saved = 'live';
        setTimeout(()=>detSetTab(saved), 50);
      }
      detTabRestore();

      function detJump(key){
        const card=document.querySelector('#page-detect .card[data-key="'+key+'"]');
        if(!card)return;
        const body=card.querySelector('.card-body');
        if(body&&body.classList.contains('collapsed')){
          const id=card.querySelector('.card-header').getAttribute('onclick');
          if(id){const m=id.match(/toggleCollapse\\(['"]([^'"]+)['"]\\)/);if(m)toggleCollapse(m[1]);}
        }
        card.scrollIntoView({behavior:'smooth',block:'start'});
      }
      document.querySelectorAll('#det-chips .det-chip').forEach(c=>{
        c.addEventListener('click',()=>{
          _detSev=c.dataset.sev;
          document.querySelectorAll('#det-chips .det-chip').forEach(x=>x.classList.remove('firing'));
          c.classList.add('firing');
          detApplyFilters();
        });
      });
        function detRenderTable(elId, rows, cols) {
          const el = document.getElementById(elId);
          if (!el) return;
          
          if (!rows || rows.length === 0) {
            el.innerHTML = '<table class="dt"><tr><td class="empty">(none)</td></tr></table>';
            return;
          }
          
          const thead = cols
          .map((c, i) => `<th onclick="detTableSort('${elId}', ${i})">${c.label}</th>`)
          .join('');
          
          const tbody = rows
          .map(r => {
            const tds = cols
            .map(c => {
              const v = c.get ? c.get(r) : r[c.key];
              const val = v === undefined || v === null ? '-' : v;
              const escaped = String(val).replace(/"/g, '&quot;');
              return `<td title="${escaped}">${val}</td>`;
            })
            .join('');
            return `<tr>${tds}</tr>`;
          })
          .join('');
          
          el.innerHTML = `<table class="dt"><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table>`;
          el._detRows = rows;
          el._detCols = cols;
        }
        function detTableSort(id,colIdx){
        const el=document.getElementById(id);if(!el||!el._detRows)return;
        const c=el._detCols[colIdx];const k=c.key;
        const prev=el._detSortK===k?el._detSortAsc:false;
        el._detSortK=k;el._detSortAsc=!prev;
        el._detRows.sort((a,b)=>{
          const av=c.get?c.get(a):a[k],bv=c.get?c.get(b):b[k];
          if(av<bv)return prev?1:-1;if(av>bv)return prev?-1:1;return 0;
        });
        detRenderTable(id,el._detRows,el._detCols);
      }
      function _ago(ms){
        if(!ms)return '-';
        const s=Math.floor((Date.now()-ms)/1000);
        if(s<60)return s+'s';
        if(s<3600)return Math.floor(s/60)+'m';
        return Math.floor(s/3600)+'h';
      }
      const DET_FEATURES_LOCAL=[
        ['pmkid','PMKID Harvest'],['eviltwin','Evil-Twin / Beacon Forgery'],['ssid_confusion','SSID Confusion'],
        ['sae','SAE DoS'],['owe','OWE Abuse'],['frag','FragAttacks'],
        ['hshk','Handshake Reconstruction'],
        ['tsf','TSF / Evil-Twin'],['jam','WiFi Interference (L2)'],['mesh_guard','Mesh Disruption'],
        ['ble_malformed','BLE Malformed'],['tracker','BLE Tracker'],['airtag','AirTag (+ Replay)'],['ble_attack','BLE Attack Tools'],
        ['rid_spoof','RID Spoof Validator'],
        ['bloom_gossip','Bloom Gossip'],['attacker_trilat','Attacker Trilat'],
        ['karma','KARMA Bait'],
        ['probe_flood','Probe Flood'],['assoc_sleep','Assoc Sleep']
      ];
      const DET_FEATURES_MESH=[
        ['mesh_deauth','Deauth'],['mesh_beacon','Beacon Flood'],
        ['mesh_auth','Auth Flood'],['mesh_assoc_sleep','Assoc Sleep'],
        ['mesh_sae','SAE DoS'],['mesh_eviltwin','Evil-Twin'],
        ['mesh_owe','OWE Abuse'],['mesh_karma','Karma'],
        ['mesh_pmkid','PMKID'],['mesh_probe_flood','Probe Flood'],
        ['mesh_hshk','Handshake/KRACK'],['mesh_frag','FragAttacks'],
        ['mesh_tsf','TSF Twin'],['mesh_jam','WiFi Jamming'],
        ['mesh_guard','Mesh Disruption']
      ];
      const DET_THRESHOLDS=[
        ['cs_copresent_ms','Follower: co-present (ms)',60000,3600000],
        ['cs_min_clusters','Follower: min node clusters',1,10],
        ['cs_persist_ms','Follower: single-node persist (ms)',60000,3600000],
        ['cs_owner_absent_pct','Follower: owner-absent %',10,100],
        ['cs_rotation_rate','BLE-spam: MACs/sec',2,50],
        ['pmkid_window','PMKID Window (ms)',1000,60000],
        ['pmkid_min_bssids','PMKID Min BSSIDs',2,10],
        ['sae_window','SAE Window (ms)',1000,60000],
        ['sae_unmatched_thresh','SAE Unmatched',3,50],
        ['probe_single_thresh','Probe Flood: 1-MAC probes /5s',10,500],
        ['probe_rand_total','Probe Flood: randomized total /5s',10,1000],
        ['probe_rand_distinct','Probe Flood: randomized distinct MACs /5s',5,500],
        ['hunt_cooldown_ms','Hunt Cooldown (ms)',5000,600000]
      ];
      let _detCfg=null;
      function detRenderConfig(){
        if(!_detCfg)return;
        // Tool-fingerprint detectors (tool/tool byte/behavior matches) split out
        // for clarity. Re-classifying probe_flood + assoc_sleep here.
        const toolKeys=['probe_flood','assoc_sleep'];
        const wifiKeys=['pmkid','eviltwin','ssid_confusion','sae','owe','frag','hshk','attacker_trilat','rid_spoof','karma'];
        const meshKeys=DET_FEATURES_MESH.map(x=>x[0]);
        const tsfKey='tsf';const bloomKey='bloom_gossip';
        function rowHtml(k,label){
          const on=_detCfg[k]===true;
          return `<div class="det-row"><div class="name">${label}</div>
            <label><input type="checkbox" data-cfg="${k}" ${on?'checked':''}> enabled</label></div>`;
        }
        function rowMesh(k,label){
          const on=_detCfg[k]===true;
          return `<div class="det-row"><div class="name">${label}</div>
            <label><input type="checkbox" data-cfg="${k}" ${on?'checked':''}></label></div>`;
        }
        const meshEl=document.getElementById('cfg-mesh');
        if(meshEl)meshEl.innerHTML=DET_FEATURES_MESH.map(p=>rowMesh(p[0],p[1])).join('');
        const threshEl=document.getElementById('cfg-thresh');
        if(threshEl){
          let threshHtml='';
          DET_THRESHOLDS.forEach(t=>{
            const v=_detCfg[t[0]]||t[2];
            threshHtml+=`<div><label style="font-size:11px;color:var(--mut);">${t[1]}</label>
              <input type="number" data-thr="${t[0]}" value="${v}" min="${t[2]}" max="${t[3]}" style="width:100%"></div>`;
          });
          threshEl.innerHTML=threshHtml;
        }
        document.querySelectorAll('#cfg-mesh input').forEach(el=>{
          el.addEventListener('change',()=>detPostCfg({[el.dataset.cfg]:el.checked}));
        });
      }
      async function detPostCfg(patch){
        Object.assign(_detCfg||(_detCfg={}),patch);
        if(typeof renderDos==='function')renderDos();
        await fetch('/api/detect/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(patch)});
      }
      // Threat-scenario groups. Keys map to existing detector toggles.
      // ssid_confusion intentionally excluded: CVE-2023-52424 is a client-side
      // supplicant flaw, not observable from an AP-side sniffer (see docs/detector-verification.md).
      // bloom_gossip + attacker_trilat are infra/response actions, not detectors -> excluded from groups.
      // NOTE: deauth detection is unconditional (no toggle); WPS/WPA3/evil_portal detectors
      // are staged and will get their own toggle keys during the detector build.
      const DET_GROUPS={
        dos:      ['sae','assoc_sleep'],
        rogue_ap: ['eviltwin','owe','karma'],
        recon:    ['pmkid','probe_flood','hshk'],
        physical: ['frag','tsf','jam'],
        mesh:     ['mesh_guard'],
        ble:      ['ble_attack','ble_malformed','tracker','airtag']
      };
      const DET_ALL_LOCAL=[...new Set(Object.keys(DET_GROUPS).filter(g=>g!=='ble').flatMap(g=>DET_GROUPS[g]))];
      const DET_ALL_MESH=['mesh_deauth','mesh_beacon','mesh_auth','mesh_assoc_sleep',
        'mesh_sae','mesh_eviltwin','mesh_owe','mesh_karma','mesh_pmkid',
        'mesh_probe_flood','mesh_hshk','mesh_frag','mesh_tsf','mesh_jam','mesh_guard'];
      // Turn a single threat group on or off (members only; leaves other detectors untouched).
      async function detGroupToggle(group){
        const members=DET_GROUPS[group]; if(!members) return;
        const cfg=_detCfg||{};
        const anyOn=members.some(k=>cfg[k]);
        await detGroup(group, !anyOn);
      }
      async function detGroup(group,on){
        const members=DET_GROUPS[group]; if(!members) return;
        const patch={}; members.forEach(k=>patch[k]=!!on);
        await detPostCfg(patch); await detLoadCfg();
        /* BLE attack group scan-trigger disabled per user 2026-05-23 (BLE scan path unreliable on this build)
        if(group==='ble'){
          if(on){
            const fd=new FormData(); fd.append('mode','1'); fd.append('forever','1');
            const r=await fetch('/scan',{method:'POST',body:fd});
            toast(r.status===409?'Radio busy — stop current scan first':'BLE scan started');
          } else {
            await fetch('/stop'); toast('BLE scan stopped');
          }
        }
        */
      }
      async function detPreset(name){
        let patch={};
        if(name==='all-on'){DET_ALL_LOCAL.forEach(k=>patch[k]=true);DET_ALL_MESH.forEach(k=>patch[k]=true);}
        else if(name==='all-off'){DET_ALL_LOCAL.forEach(k=>patch[k]=false);DET_ALL_MESH.forEach(k=>patch[k]=false);}
        else if(name==='quiet'){patch={frag:false,tsf:false,mesh_frag:false,mesh_hshk:false};}
        else if(name==='mesh-silent'){DET_ALL_MESH.forEach(k=>patch[k]=false);}
        else if(name==='mesh-all'){DET_ALL_MESH.forEach(k=>patch[k]=true);}
        await detPostCfg(patch);
        await detLoadCfg();
      }
      function detSaveThresh(){
        const patch={};
        document.querySelectorAll('input[data-thr]').forEach(el=>{
          const v=parseInt(el.value,10);
          if(!isNaN(v))patch[el.dataset.thr]=v;
        });
        detPostCfg(patch);
      }
      async function detLoadCfg(){
        _detCfg=await _jj('/api/detect/config');
        detRenderConfig();
        if(typeof renderDos==='function')renderDos();
      }
      async function detHealthTick(){
        const tab=document.getElementById('page-detect');
        if(!tab||!tab.classList.contains('active'))return;
        const h=await _jj('/api/detect/health');
        if(!h)return;
        document.getElementById('d-heap').textContent=Math.round(h.heap_free/1024)+'K (min '+Math.round(h.heap_min/1024)+'K)';
        document.getElementById('d-drops').textContent='wifi:'+h.drops.wifi+' ble:'+h.drops.ble;
        document.getElementById('d-mgated').textContent=h.drops.mesh_gated;
      }
      function detTabActive(){
        const tab=document.getElementById('page-detect');
        return tab&&tab.classList.contains('active');
      }
      async function apClientsTick(){
        try{
          const r=await fetch('/api/apclients.json'); if(!r.ok)return;
          const a=await r.json(); const el=document.getElementById('apClientsArea'); if(!el)return;
          if(!a.length){el.innerHTML='<div style="color:var(--mut);font-size:12px;">No clients yet.</div>';return;}
          const ago=ms=>ms<60000?Math.round(ms/1000)+'s':Math.round(ms/60000)+'m';
          el.innerHTML='<table class="dt"><thead><tr><th>Client MAC</th><th>Assoc #</th><th>First</th><th>Last</th></tr></thead><tbody>'
            +a.map(c=>`<tr><td style="color:var(--acc);">${c.mac}</td><td>${c.assoc}</td><td>${ago(c.first_ms_ago)} ago</td><td>${ago(c.last_ms_ago)} ago</td></tr>`).join('')
            +'</tbody></table>';
        }catch(e){console.warn('apClientsTick',e);}
      }
      async function meshCmdTick(){
        if(!detTabActive())return;
        const a=await _jsonl('/api/mesh_cmd.jsonl');
        const el=document.getElementById('meshCmdArea'); if(!el)return;
        if(!a.length){el.innerHTML='<div style="color:var(--mut);font-size:12px;">No commands logged.</div>';return;}
        const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;');
        const when=r=>{if(r.epoch&&r.epoch>946684800){const d=new Date(r.epoch*1000);return d.toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});}return Math.round((r.ts||0)/1000)+'s up';};
        el.innerHTML='<table class="dt"><thead><tr><th>Time</th><th>Radio</th><th>Command</th></tr></thead><tbody>'
          +a.slice(-100).reverse().map(r=>`<tr><td>${esc(when(r))}</td><td style="color:var(--acc);">${esc(r.src)}</td><td>${esc(r.cmd)}</td></tr>`).join('')
          +'</tbody></table>';
      }
      function detAllTicks(){
        if(!detTabActive())return;
        detectTick();pgTick();trkTick();atTick();hsTick();
        ahTick();kmTick();tsfTick();tofTick();detHealthTick();
        bfTick();pfTick();ebTick();pflTick();asTick();jammingTick();meshGuardTick();baTick();apClientsTick();meshCmdTick();
      }
      async function _jsonl(path){
        try{const r=await fetch(path);if(!r.ok)return [];const t=await r.text();
          return t.split('\n').filter(x=>x.trim()).map(x=>{try{return JSON.parse(x)}catch(_){return null}}).filter(x=>x);}
        catch(_){return []}
      }
      function _renderJsonl(elId,arr,cols){
        const el=document.getElementById(elId);if(!el)return;
        if(arr.length===0){el.textContent='--';return;}
        const rows=arr.slice(-50).reverse().map(r=>cols.map(c=>{const v=r[c];return v===undefined?'':String(v)}).join(' | '));
        el.textContent=cols.join(' | ')+'\n'+rows.join('\n');
      }
      async function bfTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/eviltwin.jsonl');
        const forge=a.filter(r=>r.reason&&r.reason.indexOf('FORGE_')===0);
        document.getElementById('bf-n').textContent=forge.length;
        _renderJsonl('bf-pre',forge,['ts','bssid','ssid','reason','rssi','ch']);
        if(forge.length>0)detMarkActive('bcnforge');
      }
      async function bfClear(){await fetch('/api/eviltwin/clear',{method:'POST'});bfTick();}
      async function pfTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/pmkid_forge.jsonl');
        document.getElementById('pf-n').textContent=a.length;
        _renderJsonl('pf-pre',a,['ts','src','sta','keyinfo','rssi','ch']);
        if(a.length>0)detMarkActive('pmkidforge');
      }
      async function pfClear(){await fetch('/api/pmkid_forge/clear',{method:'POST'});pfTick();}
      async function ebTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/eapol_bait.jsonl');
        document.getElementById('eb-n').textContent=a.length;
        _renderJsonl('eb-pre',a,['ts','src','sta','deauth_count','latency_ms','confidence','rssi']);
        if(a.length>0)detMarkActive('eapolbait');
      }
      async function ebClear(){await fetch('/api/eapol_bait/clear',{method:'POST'});ebTick();}
      async function pflTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/probe_flood.jsonl');
        document.getElementById('pfl-n').textContent=a.length;
        _renderJsonl('pfl-pre',a,['ts','ssid','hits','distinct_src','rssi','reason']);
        if(a.length>0)detMarkActive('probeflood');
      }
      async function pflClear(){await fetch('/api/probe_flood/clear',{method:'POST'});pflTick();}
      async function asTick(){if(!detTabActive())return;
        const a=await _jsonl('/api/assoc_sleep.jsonl');
        document.getElementById('as-n').textContent=a.length;
        _renderJsonl('as-pre',a,['ts','bssid','distinct_src','rssi','ch']);
        if(a.length>0)detMarkActive('assocsleep');
      }
      async function asClear(){await fetch('/api/assoc_sleep/clear',{method:'POST'});asTick();}
      async function detectAssignChannels(){await fetch('/api/channel_partition',{method:'POST'});detectTick()}
      async function detectClearRecon(){await fetch('/api/recon/clear',{method:'POST'});detectTick()}
      async function detectReloadOui(){await fetch('/api/oui/reload',{method:'POST'});detectTick()}
      detLoadCfg();
      setInterval(()=>{ if(pageActive('detect')) detAllTicks(); },5000);
      detAllTicks();
    </script>
  </body>
</html>
)HTML";
