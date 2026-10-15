/**
 * 对话内图片附件缩略图。
 *
 * 用户消息正文里的「📎 文件名: /abs/path」（由后端 userMessageContentForStorage 写入并在刷新后复用）
 * 若为图片，则通过 /api/chat-uploads/download 带鉴权拉取字节，渲染缩略图，点击放大。
 *
 * 只影响界面展示：图片是否随消息直发主模型由 AI 通道的 supports_vision 决定，
 * 与这里无关（此处不发任何模型请求）。
 */
(function () {
    'use strict';

    var IMAGE_EXT_RE = /\.(png|jpe?g|webp|gif|bmp|tiff?)$/i;
    var ATTACH_RE = /📎\s*([^:\n]+?)\s*:\s*([^\n]+)/g;
    var MAX_CACHE_ENTRIES = 40;

    /** relativePath -> objectURL（同一张图在多次渲染/滚动复用时只拉一次） */
    var blobUrls = new Map();
    var cacheOrder = [];

    function clearNode(el) {
        if (!el) return;
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    function label(key, fallback) {
        if (typeof window.t === 'function') {
            var v = window.t(key);
            if (v && v !== key) return v;
        }
        return fallback;
    }

    /** 绝对路径 → chat_uploads 下的相对路径（后端接口只接受相对路径且按此做归属校验）。 */
    function chatUploadsRelativePath(absPath) {
        var norm = String(absPath == null ? '' : absPath).trim().replace(/\\/g, '/');
        if (!norm) return '';
        var marker = '/chat_uploads/';
        var idx = norm.indexOf(marker);
        if (idx !== -1) return norm.slice(idx + marker.length);
        if (norm.indexOf('chat_uploads/') === 0) return norm.slice('chat_uploads/'.length);
        return '';
    }

    /** 从消息正文解析出可预览的图片附件（去重，非 chat_uploads 的路径不预览）。 */
    function parseImageAttachments(content) {
        var text = String(content == null ? '' : content);
        var out = [];
        var seen = {};
        var m;
        ATTACH_RE.lastIndex = 0;
        while ((m = ATTACH_RE.exec(text)) !== null) {
            var name = (m[1] || '').trim();
            var path = (m[2] || '').trim();
            if (!IMAGE_EXT_RE.test(path)) continue;
            var rel = chatUploadsRelativePath(path);
            if (!rel || seen[rel]) continue;
            seen[rel] = true;
            out.push({ name: name || rel.split('/').pop(), path: path, relativePath: rel });
        }
        return out;
    }

    function rememberBlobUrl(rel, url) {
        blobUrls.set(rel, url);
        cacheOrder.push(rel);
        while (cacheOrder.length > MAX_CACHE_ENTRIES) {
            var oldest = cacheOrder.shift();
            if (oldest === rel) continue;
            var oldUrl = blobUrls.get(oldest);
            blobUrls.delete(oldest);
            if (oldUrl && typeof URL !== 'undefined' && URL.revokeObjectURL) URL.revokeObjectURL(oldUrl);
        }
    }

    /** 释放全部缓存（切换/清空对话时调用）。 */
    function reset() {
        cacheOrder.forEach(function (rel) {
            var url = blobUrls.get(rel);
            if (url && typeof URL !== 'undefined' && URL.revokeObjectURL) URL.revokeObjectURL(url);
        });
        blobUrls.clear();
        cacheOrder = [];
    }

    function loadImageUrl(rel) {
        if (blobUrls.has(rel)) return Promise.resolve(blobUrls.get(rel));
        if (typeof apiFetch !== 'function') return Promise.reject(new Error('apiFetch unavailable'));
        return apiFetch('/api/chat-uploads/download?path=' + encodeURIComponent(rel))
            .then(function (res) {
                if (!res || !res.ok) throw new Error('HTTP ' + (res && res.status));
                return res.blob();
            })
            .then(function (blob) {
                if (!blob || !blob.size) throw new Error('empty image payload');
                var url = URL.createObjectURL(blob);
                rememberBlobUrl(rel, url);
                return url;
            });
    }

    function openLightbox(url, name) {
        if (typeof document === 'undefined' || !document.body || !url) return null;
        var overlay = document.createElement('div');
        overlay.className = 'cs-image-lightbox';
        var img = document.createElement('img');
        img.src = url;
        img.alt = name || '';
        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'cs-image-lightbox-close';
        closeBtn.textContent = '×';
        closeBtn.setAttribute('aria-label', label('chat.attachmentImageClose', '关闭'));
        function onKey(e) {
            if (e && e.key === 'Escape') close();
        }
        function close() {
            document.removeEventListener('keydown', onKey);
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        }
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) close();
        });
        closeBtn.addEventListener('click', close);
        document.addEventListener('keydown', onKey);
        overlay.appendChild(img);
        overlay.appendChild(closeBtn);
        document.body.appendChild(overlay);
        return overlay;
    }

    /** 在用户消息容器里追加图片缩略图条；无图片附件时不做任何事。 */
    function attach(container, content) {
        if (!container || typeof document === 'undefined') return;
        var items = parseImageAttachments(content);
        if (!items.length) return;
        var strip = document.createElement('div');
        strip.className = 'message-attachment-thumbs';
        items.forEach(function (item) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'message-attachment-thumb is-loading';
            btn.title = item.name;
            btn.setAttribute('aria-label', item.name);
            var state = document.createElement('span');
            state.className = 'message-attachment-thumb-state';
            state.textContent = label('chat.attachmentImageLoading', '加载中…');
            btn.appendChild(state);
            btn.addEventListener('click', function () {
                openLightbox(blobUrls.get(item.relativePath), item.name);
            });
            loadImageUrl(item.relativePath)
                .then(function (url) {
                    btn.classList.remove('is-loading');
                    clearNode(btn);
                    var img = document.createElement('img');
                    img.src = url;
                    img.alt = item.name;
                    img.loading = 'lazy';
                    btn.appendChild(img);
                })
                .catch(function () {
                    btn.classList.remove('is-loading');
                    btn.classList.add('is-failed');
                    clearNode(btn);
                    var failed = document.createElement('span');
                    failed.className = 'message-attachment-thumb-state';
                    failed.textContent = label('chat.attachmentImageFailed', '图片不可用');
                    btn.appendChild(failed);
                });
            strip.appendChild(btn);
        });
        container.appendChild(strip);
    }

    window.csChatImages = {
        attach: attach,
        reset: reset,
        // 以下为内部实现，供前端测试直接调用
        parseImageAttachments: parseImageAttachments,
        chatUploadsRelativePath: chatUploadsRelativePath,
        openLightbox: openLightbox
    };
})();
