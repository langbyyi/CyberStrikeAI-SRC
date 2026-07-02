/**
 * 项目事实图渲染（Cytoscape + ELK），供项目管理页使用。
 * 节点采用 SVG 卡片背景（图标 + 多行文字），避免 Cytoscape 原生 label 定位问题。
 */
(function (global) {
    'use strict';

    let _cy = null;
    let _graphData = null;
    let _onNodeSelect = null;
    let _onEdgeSelect = null;
    let _resizeObs = null;

    const EDGE_COLORS = {
        discovered_on: '#4F46E5',
        leads_to: '#64748B',
        enables: '#E11D48',
        exploits: '#DC2626',
        depends_on: '#0D9488',
        contains: '#6366F1',
        part_of: '#6366F1',
        supports: '#94A3B8',
        links_vuln: '#BE123C',
    };

    const CARD_PAD = 14;
    const CARD_TEXT_PAD_RIGHT = 12;
    const CARD_ICON = 36;
    const CARD_ICON_GAP = 12;
    const CARD_TEXT_X = CARD_PAD + CARD_ICON + CARD_ICON_GAP;
    const CARD_MIN_W = 300;
    const CARD_TARGET_W = 360;
    const CARD_MIN_H = 88;
    const CARD_MAX_H = 176;
    const CARD_HEADER_FS = 11;
    const CARD_HEADER_LH = 16;
    const CARD_KEY_FS = 10;
    const CARD_KEY_LH = 14;
    const CARD_SUMMARY_FS = 13;
    const CARD_SUMMARY_LH = 18;
    const CARD_SECTION_GAP = 6;
    const CARD_FONT =
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", "PingFang SC", "Microsoft YaHei", sans-serif';
    const CARD_KEY_FONT =
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace';

    function nodeTheme(type) {
        switch (type) {
            case 'target':
                return { typeLabel: '目标', typeEn: 'TARGET', accent: '#4F46E5', bgEnd: '#F5F3FF', icon: 'target' };
            case 'finding':
                return { typeLabel: '发现', typeEn: 'FINDING', accent: '#E11D48', bgEnd: '#FFF1F2', icon: 'finding', cardStyle: 'default' };
            case 'exploit':
                return { typeLabel: '利用', typeEn: 'EXPLOIT', accent: '#B45309', bgEnd: '#FFFBEB', icon: 'vulnerability', cardStyle: 'default' };
            case 'vulnerability':
                return { typeLabel: '漏洞', typeEn: 'VULN', accent: '#9333EA', bgEnd: '#F5F3FF', icon: 'vuln', cardStyle: 'default' };
            case 'auth':
                return { typeLabel: '认证', typeEn: 'AUTH', accent: '#0D9488', bgEnd: '#F0FDFA', icon: 'default' };
            case 'infra':
                return { typeLabel: '基础设施', typeEn: 'INFRA', accent: '#64748B', bgEnd: '#F8FAFC', icon: 'default' };
            case 'chain':
                return { typeLabel: '攻击链', typeEn: 'CHAIN', accent: '#7C3AED', bgEnd: '#F5F3FF', icon: 'vulnerability' };
            case 'poc':
                return { typeLabel: 'POC', typeEn: 'POC', accent: '#C2410C', bgEnd: '#FFEDD5', icon: 'vulnerability' };
            case 'business':
                return { typeLabel: '业务', typeEn: 'BUSINESS', accent: '#0369A1', bgEnd: '#F0F9FF', icon: 'default' };
            case 'missing':
                return { typeLabel: '缺失', typeEn: 'MISSING', accent: '#CBD5E1', bgEnd: '#F1F5F9', icon: 'default' };
            default:
                return { typeLabel: '备注', typeEn: 'NOTE', accent: '#94A3B8', bgEnd: '#F8FAFC', icon: 'default' };
        }
    }

    function escapeXml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&apos;');
    }

    function escapeHtml(str) {
        return escapeXml(str);
    }

    function buildStatusBadge(confidence) {
        const conf = (confidence || '').toLowerCase();
        if (conf === 'tentative') return '待确认';
        if (conf === 'deprecated') return '已废弃';
        return '';
    }

    function buildHeaderText(theme, statusBadge) {
        const line = (theme.typeEn || '') + ' · ' + (theme.typeLabel || '');
        return statusBadge ? line + ' · ' + statusBadge : line;
    }

    function isWideChar(ch) {
        const code = ch.codePointAt(0) || 0;
        if (code >= 0x4e00 && code <= 0x9fff) return true;
        if (code >= 0x3400 && code <= 0x4dbf) return true;
        if (code >= 0xf900 && code <= 0xfaff) return true;
        if (code >= 0xff00 && code <= 0xffef) return true;
        return /[·：，。；！？【】（）《》、「」]/.test(ch);
    }

    function charWidth(ch, fontSize, bold) {
        const scale = bold ? 1.05 : 1;
        if (ch === ' ') return fontSize * 0.3 * scale;
        if (isWideChar(ch)) return fontSize * scale;
        return fontSize * 0.58 * scale;
    }

    function lineWidth(text, fontSize, bold) {
        let width = 0;
        for (const ch of text) width += charWidth(ch, fontSize, bold);
        return width;
    }

    function wrapTextLines(text, maxWidth, fontSize, maxLines, bold) {
        const raw = String(text || '').replace(/\s+/g, ' ').trim();
        if (!raw) return ['—'];
        const safeWidth = Math.max(40, maxWidth - 4);
        const chars = [...raw];
        const lines = [];
        let index = 0;
        while (index < chars.length && lines.length < maxLines) {
            let line = '';
            let width = 0;
            while (index < chars.length) {
                const ch = chars[index];
                const nextWidth = charWidth(ch, fontSize, bold);
                if (line && width + nextWidth > safeWidth) break;
                line += ch;
                width += nextWidth;
                index += 1;
                if (width >= safeWidth) break;
            }
            if (line) lines.push(line);
        }
        if (index < chars.length && lines.length) {
            let last = lines[lines.length - 1];
            while (last.length > 1 && lineWidth(last + '…', fontSize, bold) > safeWidth) {
                last = last.slice(0, -1);
            }
            lines[lines.length - 1] = last + '…';
        }
        return lines.length ? lines : ['—'];
    }

    function cardTextWidth(nodeWidth) {
        return nodeWidth - CARD_TEXT_X - CARD_PAD - CARD_TEXT_PAD_RIGHT;
    }

    function computeNodeLayout(type, summary, statusBadge, theme, factKey) {
        const width = type === 'target' ? CARD_TARGET_W : CARD_MIN_W;
        const textW = cardTextWidth(width);
        const t = theme || nodeTheme(type);
        const headerLines = wrapTextLines(buildHeaderText(t, statusBadge), textW, CARD_HEADER_FS, 2, true);
        const keyText = String(factKey || '').trim();
        const keyLines = keyText ? wrapTextLines(keyText, textW, CARD_KEY_FS, 2, false) : [];
        const summaryLines = wrapTextLines(summary, textW, CARD_SUMMARY_FS, keyLines.length ? 3 : 4, true);
        const keyBlockHeight = keyLines.length
            ? CARD_SECTION_GAP + keyLines.length * CARD_KEY_LH + CARD_SECTION_GAP
            : CARD_SECTION_GAP;
        const height = Math.min(
            CARD_MAX_H,
            Math.max(
                CARD_MIN_H,
                CARD_PAD +
                    headerLines.length * CARD_HEADER_LH +
                    keyBlockHeight +
                    summaryLines.length * CARD_SUMMARY_LH +
                    CARD_PAD,
            ),
        );
        return {
            width,
            height,
            headerLines,
            keyLines,
            summaryLines,
            searchLabel: [headerLines.join(' '), keyLines.join(' '), summaryLines.join(' ')]
                .filter(Boolean)
                .join('\n'),
        };
    }

    function svgIconGroup(kind, color, x, y) {
        const scale = (CARD_ICON / 24).toFixed(3);
        if (kind === 'target') {
            return (
                `<g transform="translate(${x}, ${y}) scale(${scale})">` +
                `<circle cx="12" cy="12" r="6" fill="none" stroke="${color}" stroke-width="2"/>` +
                `<circle cx="12" cy="12" r="2.5" fill="${color}"/></g>`
            );
        }
        if (kind === 'finding') {
            return (
                `<g transform="translate(${x}, ${y}) scale(${scale})">` +
                `<circle cx="10" cy="10" r="6" fill="none" stroke="${color}" stroke-width="2"/>` +
                `<line x1="14.5" y1="14.5" x2="19" y2="19" stroke="${color}" stroke-width="2" stroke-linecap="round"/></g>`
            );
        }
        if (kind === 'vuln') {
            return (
                `<g transform="translate(${x}, ${y}) scale(${scale})">` +
                `<path d="M12 2.5l7.5 3v6.2c0 4.6-3.1 8.1-7.5 9.3-4.4-1.2-7.5-4.7-7.5-9.3V5.5z" fill="${color}" fill-opacity="0.12" stroke="${color}" stroke-width="2"/>` +
                `<line x1="12" y1="8.5" x2="12" y2="12.5" stroke="${color}" stroke-width="2" stroke-linecap="round"/>` +
                `<circle cx="12" cy="15.5" r="1.1" fill="${color}"/></g>`
            );
        }
        if (kind === 'vulnerability') {
            return (
                `<g transform="translate(${x}, ${y}) scale(${scale})">` +
                `<path d="M12 3l9 16H3z" fill="none" stroke="${color}" stroke-width="2"/>` +
                `<line x1="12" y1="9" x2="12" y2="13" stroke="${color}" stroke-width="2"/>` +
                `<circle cx="12" cy="16" r="1" fill="${color}"/></g>`
            );
        }
        return (
            `<g transform="translate(${x}, ${y}) scale(${scale})">` +
            `<circle cx="12" cy="12" r="5" fill="${color}" opacity="0.85"/></g>`
        );
    }

    function buildNodeCardSvgUrl(theme, layout, confidence) {
        const { width, height, headerLines, keyLines, summaryLines } = layout;
        const accent = theme.accent;
        const bgEnd = theme.bgEnd;
        const conf = (confidence || '').toLowerCase();
        const isTentative = conf === 'tentative';
        const isDeprecated = conf === 'deprecated';
        const iconX = CARD_PAD;
        const iconY = (height - CARD_ICON) / 2;
        const headerY = CARD_PAD + CARD_HEADER_FS;
        const keyY = CARD_PAD + headerLines.length * CARD_HEADER_LH + CARD_SECTION_GAP + CARD_KEY_FS;
        const summaryY =
            CARD_PAD +
            headerLines.length * CARD_HEADER_LH +
            (keyLines.length
                ? CARD_SECTION_GAP + keyLines.length * CARD_KEY_LH + CARD_SECTION_GAP
                : CARD_SECTION_GAP) +
            CARD_SUMMARY_FS;

        const stroke = isTentative
            ? `stroke="${accent}" stroke-width="1.5" stroke-dasharray="8 5" stroke-opacity="0.9"`
            : `stroke="${accent}" stroke-width="1.5" stroke-opacity="0.72"`;

        const headerSvg = headerLines
            .map(
                (line, i) =>
                    `<text x="${CARD_TEXT_X}" y="${headerY + i * CARD_HEADER_LH}" font-size="${CARD_HEADER_FS}" font-weight="700" fill="${accent}" fill-opacity="0.88" font-family='${CARD_FONT}'>${escapeXml(line)}</text>`,
            )
            .join('');

        const keySvg = keyLines
            .map(
                (line, i) =>
                    `<text x="${CARD_TEXT_X}" y="${keyY + i * CARD_KEY_LH}" font-size="${CARD_KEY_FS}" font-weight="500" fill="#64748b" font-family='${CARD_KEY_FONT}'>${escapeXml(line)}</text>`,
            )
            .join('');

        const summarySvg = summaryLines
            .map(
                (line, i) =>
                    `<text x="${CARD_TEXT_X}" y="${summaryY + i * CARD_SUMMARY_LH}" font-size="${CARD_SUMMARY_FS}" font-weight="600" fill="#0f172a" font-family='${CARD_FONT}'>${escapeXml(line)}</text>`,
            )
            .join('');

        const textClipW = width - CARD_TEXT_X - CARD_PAD - 2;
        const textClipH = height - CARD_PAD * 2 + 4;

        const svg =
            `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">` +
            `<defs><linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">` +
            `<stop offset="0%" stop-color="#FFFFFF"/><stop offset="100%" stop-color="${bgEnd}"/></linearGradient>` +
            `<clipPath id="textClip"><rect x="${CARD_TEXT_X}" y="${CARD_PAD - 2}" width="${textClipW}" height="${textClipH}"/></clipPath></defs>` +
            `<g${isDeprecated ? ' opacity="0.55"' : ''}>` +
            `<rect x="0.75" y="0.75" width="${width - 1.5}" height="${height - 1.5}" rx="12" fill="url(#bg)" ${stroke}/>` +
            svgIconGroup(theme.icon, accent, iconX, iconY) +
            `<g clip-path="url(#textClip)">${headerSvg}${keySvg}${summarySvg}</g>` +
            `</g></svg>`;

        try {
            return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
        } catch (e) {
            return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
        }
    }

    function destroy() {
        if (_resizeObs) {
            _resizeObs.disconnect();
            _resizeObs = null;
        }
        if (_cy) {
            _cy.destroy();
            _cy = null;
        }
        _graphData = null;
    }

    function observeContainerResize(container) {
        if (_resizeObs) {
            _resizeObs.disconnect();
            _resizeObs = null;
        }
        if (!container || typeof ResizeObserver === 'undefined') return;
        _resizeObs = new ResizeObserver(() => {
            if (_cy) {
                try {
                    _cy.resize();
                } catch (e) {
                    console.warn('graph resize', e);
                }
            }
        });
        _resizeObs.observe(container);
    }

    function centerGraph() {
        if (!_cy) return;
        try {
            _cy.resize();
            _cy.fit(undefined, 56);
            if (_cy.zoom() < 0.65) {
                _cy.zoom(0.65);
                _cy.center();
            }
        } catch (e) {
            console.warn('centerGraph', e);
        }
    }

    // ELK 分层（仅影响节点纵向位置，不修改边的 source/target）
    function pathGraphNodeLayer(type, factKey) {
        const key = (factKey || '').toLowerCase();
        if (key.startsWith('vuln:')) return '4';
        const t = (type || '').toLowerCase();
        if (t === 'target') return '0';
        if (t === 'infra' || t === 'auth' || t === 'business') return '1';
        if (t === 'exploit' || t === 'poc') return '3';
        if (t === 'vulnerability' || t === 'vuln') return '3';
        if (t === 'chain' || t === 'finding') return '2';
        if (t === 'note') return '2';
        return '2';
    }

    function applyElkLayout(validEdges, isComplex) {
        const layoutOptions = {
            name: 'breadthfirst',
            directed: true,
            spacingFactor: isComplex ? 3.0 : 2.5,
            padding: 40,
        };
        const elkInstance = typeof ELK !== 'undefined' ? new ELK() : null;
        if (!elkInstance) {
            const layout = _cy.layout(layoutOptions);
            layout.one('layoutstop', () => setTimeout(centerGraph, 100));
            layout.run();
            return;
        }
        const nodeGap = isComplex ? 45 : 60;
        const layerGap = isComplex ? 70 : 95;
        const elkGraph = {
            id: 'root',
            layoutOptions: {
                'elk.algorithm': 'layered',
                'elk.direction': 'DOWN',
                'elk.spacing.nodeNode': String(nodeGap),
                'elk.layered.spacing.nodeNodeBetweenLayers': String(layerGap),
                'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
            },
            children: (_graphData.nodes || []).map((node) => {
                const n = _cy ? _cy.getElementById(node.id) : null;
                const w = n.length ? n.data('nodeWidth') : node.type === 'target' ? CARD_TARGET_W : CARD_MIN_W;
                const h = n.length ? n.data('nodeHeight') : CARD_MIN_H;
                const nodeKey = node.fact_key || node.id;
                return {
                    id: node.id,
                    width: w,
                    height: h,
                    layoutOptions: {
                        'org.eclipse.elk.layered.layering.layerId': pathGraphNodeLayer(node.type, nodeKey),
                    },
                };
            }),
            edges: validEdges.map((edge) => ({
                id: edge.id,
                sources: [edge.source],
                targets: [edge.target],
            })),
        };
        elkInstance
            .layout(elkGraph)
            .then((laidOut) => {
                (laidOut.children || []).forEach((elkNode) => {
                    const cyNode = _cy.getElementById(elkNode.id);
                    if (cyNode.length && elkNode.x != null) {
                        cyNode.position({
                            x: elkNode.x + (elkNode.width || 0) / 2,
                            y: elkNode.y + (elkNode.height || 0) / 2,
                        });
                    }
                });
                setTimeout(centerGraph, 120);
            })
            .catch(() => {
                const layout = _cy.layout(layoutOptions);
                layout.one('layoutstop', () => setTimeout(centerGraph, 100));
                layout.run();
            });
    }

    function render(container, graphData, options) {
        if (!container || typeof cytoscape === 'undefined') {
            if (container) {
                container.innerHTML = '<div class="error-message">Cytoscape 未加载</div>';
            }
            return null;
        }
        destroy();
        _graphData = graphData || { nodes: [], edges: [] };
        _onNodeSelect = options && options.onNodeSelect;
        _onEdgeSelect = options && options.onEdgeSelect;

        const nodes = _graphData.nodes || [];
        const edges = _graphData.edges || [];
        if (!nodes.length) {
            const title = (options && options.emptyTitle) || '';
            const hint = (options && options.emptyText) || '暂无事实关系';
            const steps = (options && options.emptySteps) || [];
            const actionLabel = options && options.emptyActionLabel;
            const stepsHtml = steps.length
                ? '<ol class="project-fact-graph-empty-steps">' +
                  steps.map((s) => '<li>' + escapeHtml(String(s)) + '</li>').join('') +
                  '</ol>'
                : '';
            const actionHtml =
                actionLabel && options.onEmptyAction
                    ? '<button type="button" class="btn-primary btn-small project-fact-graph-empty-cta">' +
                      escapeHtml(actionLabel) +
                      '</button>'
                    : '';
            container.innerHTML =
                '<div class="project-fact-graph-empty">' +
                '<div class="project-fact-graph-empty-icon" aria-hidden="true">' +
                '<svg width="48" height="48" viewBox="0 0 24 24" fill="none"><circle cx="6" cy="6" r="2.5" fill="#4F46E5" opacity="0.9"/><circle cx="18" cy="6" r="2.5" fill="#E11D48" opacity="0.9"/><circle cx="12" cy="18" r="2.5" fill="#0D9488" opacity="0.9"/>' +
                '<path d="M8 7l4 9M16 7l-4 9M8 7h8" stroke="#CBD5E1" stroke-width="1.5" stroke-linecap="round"/></svg>' +
                '</div>' +
                (title ? '<h4 class="project-fact-graph-empty-title">' + escapeHtml(title) + '</h4>' : '') +
                '<p class="project-fact-graph-empty-hint">' + escapeHtml(hint) + '</p>' +
                stepsHtml +
                actionHtml +
                '</div>';
            const cta = container.querySelector('.project-fact-graph-empty-cta');
            if (cta && typeof options.onEmptyAction === 'function') {
                cta.addEventListener('click', options.onEmptyAction);
            }
            return null;
        }

        container.innerHTML = '';
        const isComplex = nodes.length > 15 || edges.length > 25;
        const elements = [];
        const nodeIds = new Set();

        nodes.forEach((node) => {
            nodeIds.add(node.id);
            const visualType = resolveGraphNodeType(node);
            const theme = nodeTheme(visualType);
            const factKey = node.fact_key || node.id;
            const summary = (node.summary || node.label || '').trim() || '—';
            const statusBadge = buildStatusBadge(node.confidence);
            const layout = computeNodeLayout(visualType, summary, statusBadge, theme, factKey);
            elements.push({
                data: {
                    id: node.id,
                    label: layout.searchLabel,
                    factKey: node.fact_key || node.id,
                    category: node.category || '',
                    type: visualType,
                    typeLabel: theme.typeLabel,
                    typeEn: theme.typeEn,
                    accentColor: theme.accent,
                    statusBadge: statusBadge,
                    confidence: node.confidence || '',
                    nodeWidth: layout.width,
                    nodeHeight: layout.height,
                    cardSvgUrl: buildNodeCardSvgUrl(theme, layout, node.confidence),
                },
            });
        });

        const validEdges = [];
        edges.forEach((edge, idx) => {
            if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return;
            const id = edge.id || 'e-' + idx;
            validEdges.push({ ...edge, id });
            elements.push({
                data: {
                    id,
                    source: edge.source,
                    target: edge.target,
                    type: edge.type || 'leads_to',
                    confidence: edge.confidence || 'confirmed',
                },
            });
        });

        _cy = cytoscape({
            container,
            elements,
            style: [
                {
                    selector: 'node',
                    style: {
                        label: '',
                        width: (ele) => ele.data('nodeWidth') || CARD_MIN_W,
                        height: (ele) => ele.data('nodeHeight') || CARD_MIN_H,
                        shape: 'round-rectangle',
                        'background-color': '#ffffff',
                        'background-image': (ele) => ele.data('cardSvgUrl') || 'none',
                        'background-width': (ele) => (ele.data('nodeWidth') || CARD_MIN_W) + 'px',
                        'background-height': (ele) => (ele.data('nodeHeight') || CARD_MIN_H) + 'px',
                        'background-position-x': '50%',
                        'background-position-y': '50%',
                        'background-fit': 'none',
                        'border-width': 0,
                        'background-opacity': 1,
                    },
                },
                {
                    selector: 'edge',
                    style: {
                        width: 2.2,
                        'line-color': (ele) => EDGE_COLORS[ele.data('type')] || '#CBD5E1',
                        'target-arrow-color': (ele) => EDGE_COLORS[ele.data('type')] || '#CBD5E1',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        opacity: (ele) => (ele.data('confidence') === 'tentative' ? 0.55 : 0.9),
                        'line-style': (ele) => (ele.data('confidence') === 'tentative' ? 'dashed' : 'solid'),
                    },
                },
                {
                    selector: 'edge:selected',
                    style: {
                        width: 3.5,
                        opacity: 1,
                        'line-color': '#4F46E5',
                        'target-arrow-color': '#4F46E5',
                    },
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-width': 3,
                        'border-color': '#4F46E5',
                        'border-opacity': 1,
                    },
                },
            ],
            minZoom: 0.35,
            maxZoom: 3,
        });

        _cy.on('tap', 'node', (evt) => {
            const d = evt.target.data();
            const key = d.factKey || d.id;
            if (_connectMode && _connectPick) {
                _connectPick(key);
                return;
            }
            if (typeof _onNodeSelect === 'function') {
                _onNodeSelect(key, d);
            }
        });

        _cy.on('tap', 'edge', (evt) => {
            if (_connectMode && _connectPick) return;
            const d = evt.target.data();
            if (typeof _onEdgeSelect === 'function') {
                _onEdgeSelect(d.id, d);
            }
        });

        _cy.on('tap', (evt) => {
            if (evt.target === _cy) {
                clearEdgeSelection();
            }
        });

        applyElkLayout(validEdges, isComplex);
        observeContainerResize(container);
        return _cy;
    }

    function filterBySearch(query) {
        if (!_cy) return;
        const q = (query || '').trim().toLowerCase();
        _cy.nodes().forEach((n) => {
            if (!q) {
                n.style('opacity', 1);
                return;
            }
            const text = (
                (n.data('label') || '') +
                ' ' +
                (n.data('factKey') || '') +
                ' ' +
                (n.data('typeLabel') || '')
            ).toLowerCase();
            n.style('opacity', text.includes(q) ? 1 : 0.15);
        });
        _cy.edges().forEach((e) => {
            e.style('opacity', q ? 0.12 : 0.9);
        });
    }

    let _connectMode = false;
    let _connectPick = null;

    function selectEdge(edgeId) {
        if (!_cy || !edgeId) return;
        _cy.elements().unselect();
        const edge = _cy.getElementById(edgeId);
        if (edge.length) edge.select();
    }

    function clearEdgeSelection() {
        if (!_cy) return;
        _cy.elements().unselect();
    }

    function setConnectMode(enabled, onPick) {
        _connectMode = !!enabled;
        _connectPick = typeof onPick === 'function' ? onPick : null;
        if (_cy) {
            _cy.userPanningEnabled(!_connectMode);
        }
    }

    /** 与后端 GraphNodeType 一致：优先 category，vuln: 合成节点例外；无 category 时回退 type/key。 */
    function resolveGraphNodeType(node) {
        if (!node) return 'note';
        const key = String(node.fact_key || node.id || '').toLowerCase();
        if (key.startsWith('vuln:')) return 'vulnerability';
        const cat = String(node.category || '').toLowerCase();
        if (cat) {
            if (cat === 'vuln') return 'vulnerability';
            if (cat === 'missing') return 'missing';
            return cat;
        }
        const t = String(node.type || '').toLowerCase();
        if (t === 'vuln') return 'vulnerability';
        if (t) return t;
        if (key.startsWith('target/')) return 'target';
        if (key.startsWith('exploit/') || key.startsWith('evidence/')) return 'exploit';
        if (key.startsWith('poc/')) return 'poc';
        if (key.startsWith('chain/')) return 'chain';
        if (key.startsWith('finding/')) return 'finding';
        if (key.startsWith('auth/')) return 'auth';
        if (key.startsWith('infra/') || key.startsWith('business/')) return 'infra';
        return 'note';
    }

    global.ProjectFactGraph = {
        render,
        destroy,
        center: centerGraph,
        filterBySearch,
        setConnectMode,
        selectEdge,
        clearEdgeSelection,
        nodeTheme,
        resolveGraphNodeType,
    };
})(typeof window !== 'undefined' ? window : globalThis);
