// ==UserScript==
// @name         修复版视频倍速劫持脚本
// @namespace    http://tampermonkey.net/
// @version      1.1
// @description  绕过网页对 playbackRate 的限制和检测，强制保持指定倍速，兼容Chrome 125+/Edge 新版浏览器
// @match        *://*/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

/**
 * 高级视频倍速劫持脚本
 * 功能：绕过网页对 playbackRate 的限制和检测，强制保持指定倍速。
 * 使用方法：将代码复制到浏览器控制台 Console 执行，或作为 Tampermonkey 油猴脚本运行。
 */

(function() {
    'use strict';

    // ================= 配置区域 =================
    const CONFIG = {
        targetSpeed: 16.0,      // 目标播放倍速，可自行修改为你需要的数值
        fakeSpeed: 1.0,         // 向网页脚本报告的“伪装”速度（用于欺骗站点的倍速检测）
        enableFake: true,       // 是否启用伪装模式（true: 网页检测到的是1倍速; false: 网页可获取真实运行速度）
        checkInterval: 500,     // 兜底检查间隔（毫秒），防止站点脚本重置速度
        debug: false,           // 是否开启调试日志，排查脚本异常时可改为true
        enableRadicalMode: false // 是否开启激进实例级重定义模式，仅在高防护站点倍速被拦截时开启
    };


const log = (...args) => CONFIG.debug && console.log('[SpeedHijack]', ...args);

// ================= 可视化控制面板UI实现 =================
function createControlPanel() {
    // 避免重复创建面板
    if (document.querySelector('#speedHijackPanel')) return;

    // 创建面板容器
    const panel = document.createElement('div');
    panel.id = 'speedHijackPanel';
    panel.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        width: 260px;
        padding: 16px;
        background: rgba(20, 20, 20, 0.92);
        color: #fff;
        border-radius: 10px;
        z-index: 999999;
        font-family: system-ui, -apple-system, sans-serif;
        font-size: 14px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.4);
        user-select: none;
        backdrop-filter: blur(6px);
        border: 1px solid rgba(255,255,255,0.1);
    `;

    // 面板标题
    const title = document.createElement('div');
    title.innerText = '视频倍速控制';
    title.style.cssText = `
        font-weight: 600;
        font-size: 15px;
        margin-bottom: 14px;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(255,255,255,0.15);
        cursor: move;
    `;
    panel.appendChild(title);

    // 倍速选择区域
    const speedSection = document.createElement('div');
    speedSection.style.marginBottom = '14px';
    speedSection.innerHTML = `
        <div style="margin-bottom: 6px; font-weight: 500;">当前倍速: <span id="speedValue">${CONFIG.targetSpeed}</span>x</div>
        <input type="range" id="speedSlider" min="0.25" max="16" step="0.25" value="${CONFIG.targetSpeed}"
               style="width: 100%; accent-color: #409eff; margin-bottom: 8px;">
        <div style="display: flex; gap: 6px; flex-wrap: wrap;">
            <button data-speed="0.5" style="flex: 1; padding: 4px 6px; border-radius: 4px; border: none; background: #333; color: #fff; cursor: pointer;">0.5x</button>
            <button data-speed="1" style="flex: 1; padding: 4px 6px; border-radius: 4px; border: none; background: #333; color: #fff; cursor: pointer;">1x</button>
            <button data-speed="2" style="flex: 1; padding: 4px 6px; border-radius: 4px; border: none; background: #333; color: #fff; cursor: pointer;">2x</button>
            <button data-speed="3" style="flex: 1; padding: 4px 6px; border-radius: 4px; border: none; background: #333; color: #fff; cursor: pointer;">3x</button>
            <button data-speed="5" style="flex: 1; padding: 4px 6px; border-radius: 4px; border: none; background: #333; color: #fff; cursor: pointer;">5x</button>
        </div>
    `;
    panel.appendChild(speedSection);

    // 模式开关区域
    const modeSection = document.createElement('div');
    modeSection.style.cssText = `
        display: flex;
        flex-direction: column;
        gap: 10px;
    `;
    modeSection.innerHTML = `
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
            <input type="checkbox" id="fakeModeSwitch" ${CONFIG.enableFake ? 'checked' : ''}>
            <span>启用伪装倍速（欺骗站点检测）</span>
        </label>
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
            <input type="checkbox" id="radicalModeSwitch" ${CONFIG.enableRadicalMode ? 'checked' : ''}>
            <span>开启激进拦截模式（高防护站点适用）</span>
        </label>
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
            <input type="checkbox" id="debugModeSwitch" ${CONFIG.debug ? 'checked' : ''}>
            <span>开启调试日志</span>
        </label>
    `;
    panel.appendChild(modeSection);

    // 添加到页面
    document.body.appendChild(panel);

    // ------------------ 绑定UI交互逻辑 ------------------
    // 倍速滑块联动
    const speedSlider = panel.querySelector('#speedSlider');
    const speedValue = panel.querySelector('#speedValue');
    speedSlider.addEventListener('input', e => {
        const newSpeed = parseFloat(e.target.value);
        CONFIG.targetSpeed = newSpeed;
        speedValue.innerText = newSpeed;
        // 即时更新所有正在播放的视频速度
        document.querySelectorAll('video').forEach(video => {
            if (!video.paused) {
                try {
                    Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(video, newSpeed);
                } catch (err) {
                    video.playbackRate = newSpeed;
                }
            }
        });
    });

    // 快捷倍速按钮
    speedSection.querySelectorAll('button[data-speed]').forEach(btn => {
        btn.addEventListener('click', e => {
            const newSpeed = parseFloat(e.target.dataset.speed);
            speedSlider.value = newSpeed;
            speedValue.innerText = newSpeed;
            CONFIG.targetSpeed = newSpeed;
            document.querySelectorAll('video').forEach(video => {
                if (!video.paused) {
                    try {
                        Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(video, newSpeed);
                    } catch (err) {
                        video.playbackRate = newSpeed;
                    }
                }
            });
        });
    });

    // 伪装模式开关
    panel.querySelector('#fakeModeSwitch').addEventListener('change', e => {
        CONFIG.enableFake = e.target.checked;
        log(`伪装模式已${e.target.checked ? '开启' : '关闭'}`);
    });

    // 激进模式开关，修复原脚本的判断逻辑错误
    panel.querySelector('#radicalModeSwitch').addEventListener('change', e => {
        CONFIG.enableRadicalMode = e.target.checked;
        if (e.target.checked) {
            // 开启后为已存在的所有视频补做实例级重定义，修正原脚本的多余判断
            document.querySelectorAll('video').forEach(video => {
                try {
                    Object.defineProperty(video, 'playbackRate', {
                        get: function() {
                            if (CONFIG.enableFake) return CONFIG.fakeSpeed;
                            return Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').get.call(this);
                        },
                        set: function(val) {
                            log(`拦截设置请求: ${val} -> ${CONFIG.targetSpeed}`);
                            Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(this, CONFIG.targetSpeed);
                        },
                        configurable: true,
                        enumerable: true
                    });
                    video._isHijacked = true;
                } catch (e) {}
            });
        }
        log(`激进模式已${e.target.checked ? '开启' : '关闭'}`);
    });

    // 调试模式开关
    panel.querySelector('#debugModeSwitch').addEventListener('change', e => {
        CONFIG.debug = e.target.checked;
        log(`调试日志已${e.target.checked ? '开启' : '关闭'}`);
    });

    // 面板拖动功能
    let isDragging = false, offsetX, offsetY;
    title.addEventListener('mousedown', e => {
        isDragging = true;
        offsetX = e.clientX - panel.offsetLeft;
        offsetY = e.clientY - panel.offsetTop;
        panel.style.transition = 'none';
    });
    document.addEventListener('mousemove', e => {
        if (!isDragging) return;
        e.preventDefault();
        panel.style.left = `${e.clientX - offsetX}px`;
        panel.style.top = `${e.clientY - offsetY}px`;
        panel.style.right = 'auto';
    });
    document.addEventListener('mouseup', () => isDragging = false);
}

// ================= 核心劫持逻辑 =================

/**
 * 对单个 Video 元素应用劫持
 * @param {HTMLVideoElement} video
 */
function hijackVideoElement(video) {
    if (!video || video.tagName !== 'VIDEO') return;

    // 避免重复劫持
    if (video._isHijacked) return;
    video._isHijacked = true;

    log('正在劫持视频元素:', video);

    // 1. 强制设置初始速度
    try {
        Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(video, CONFIG.targetSpeed);
    } catch (e) {
        video.playbackRate = CONFIG.targetSpeed;
    }

    // 2. 监听 ratechange 事件，防止网页重置速度
    // 使用 capture: true 确保在网页脚本之前触发
    video.addEventListener('ratechange', (event) => {
        const currentRate = event.target.playbackRate;
        if (Math.abs(currentRate - CONFIG.targetSpeed) > 0.01) {
            log(`检测到速度被重置为 ${currentRate}，强制改回 ${CONFIG.targetSpeed}`);
            // 使用 requestAnimationFrame 避免同步修改导致的潜在冲突
            requestAnimationFrame(() => {
                try {
                    // 尝试直接调用原型 setter，绕过可能的实例级拦截
                    Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(event.target, CONFIG.targetSpeed);
                } catch (err) {
                    event.target.playbackRate = CONFIG.targetSpeed;
                }
            });
        }
    }, true);

    // 3. 激进模式：实例级属性重定义，绕过站点在视频元素上的单独属性拦截
    if (CONFIG.enableRadicalMode) {
        try {
            Object.defineProperty(video, 'playbackRate', {
                get: function() {
                    // 欺骗网页：返回伪装速度
                    if (CONFIG.enableFake) return CONFIG.fakeSpeed;
                    // 否则返回真实速度
                    return Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').get.call(this);
                },
                set: function(val) {
                    // 拦截所有设置请求，统一改为目标倍速
                    log(`拦截设置请求: ${val} -> ${CONFIG.targetSpeed}`);
                    Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'playbackRate').set.call(this, CONFIG.targetSpeed);
                },
                configurable: true,
                enumerable: true
            });
            log('实例级属性重定义完成');
        } catch (e) {
            log('实例级属性重定义失败', e);
        }
    }
}

/**
 * 劫持 HTMLMediaElement 原型链
 * 这会影响页面后续创建的所有 video/audio 元素
 */
function hijackPrototype() {
    const proto = HTMLMediaElement.prototype;
    const originalDesc = Object.getOwnPropertyDescriptor(proto, 'playbackRate');

    if (!originalDesc) {
        console.warn('[SpeedHijack] 无法获取原始 playbackRate 描述符');
        return;
    }

    // 保存原始 setter/getter 引用
    const originalGetter = originalDesc.get;
    const originalSetter = originalDesc.set;

    Object.defineProperty(proto, 'playbackRate', {
        get: function() {
            // 如果启用伪装，对所有查询返回 fakeSpeed
            if (CONFIG.enableFake) {
                return CONFIG.fakeSpeed;
            }
            return originalGetter.call(this);
        },
        set: function(value) {
            // 策略：如果网页试图设置速度，我们强制将其修正为目标速度
            if (value !== CONFIG.targetSpeed) {
                log(`原型层拦截: 试图设置为 ${value}，强制改为 ${CONFIG.targetSpeed}`);
                originalSetter.call(this, CONFIG.targetSpeed);
            } else {
                originalSetter.call(this, value);
            }
        },
        configurable: true,
        enumerable: true
    });

    log('原型链劫持成功');
}

// ================= 监控与初始化 =================

/**
 * 使用 MutationObserver 监控 DOM 变化，自动劫持页面中新出现的动态加载视频
 */
function initObserver() {
    // 处理页面初始加载阶段还未生成 document.body 的边缘场景
    if (!document.body) {
        const tempObserver = new MutationObserver(() => {
            if (document.body) {
                tempObserver.disconnect();
                initObserver();
                // body加载完成后创建控制面板
                createControlPanel();
            }
        });
        tempObserver.observe(document.documentElement, { childList: true });
        return;
    }
    // 如果body已存在，直接创建面板
    createControlPanel();

    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (node.tagName === 'VIDEO') {
                        hijackVideoElement(node);
                    }
                    // 检查子节点中是否有嵌套的视频元素
                    const videos = node.querySelectorAll ? node.querySelectorAll('video') : [];
                    videos.forEach(hijackVideoElement);
                }
            });
        });
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    log('DOM 观察器已启动');
}

/**
 * 兜底定时器：按配置间隔检查所有视频的速度，彻底规避漏劫持的场景
 */
function startFallbackChecker() {
    setInterval(() => {
        const videos = document.querySelectorAll('video');
        videos.forEach(video => {
            if (!video.paused && Math.abs(video.playbackRate - CONFIG.targetSpeed) > 0.1) {
                log(`兜底修正: ${video.playbackRate} -> ${CONFIG.targetSpeed}`);
                video.playbackRate = CONFIG.targetSpeed;
            }
        });
    }, CONFIG.checkInterval);
}

// ================= 启动入口 =================

function init() {
    // 1. 优先劫持原型链，在站点脚本前完成覆盖
    hijackPrototype();

    // 2. 处理页面上已经存在的所有视频元素
    document.querySelectorAll('video').forEach(hijackVideoElement);

    // 3. 启动 DOM 动态监控
    initObserver();

    // 4. 启动兜底定时检查
    startFallbackChecker();

    console.log(`[SpeedHijack] 初始化完成。目标速度: ${CONFIG.targetSpeed}x, 伪装模式: ${CONFIG.enableFake}`);
}

// @run-at document-start 模式下直接执行初始化，无需等待DOMContentLoaded
init();
})();
