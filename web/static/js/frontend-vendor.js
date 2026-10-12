// Large optional libraries load only when their feature is used.
(function () {
    var pending = Object.create(null);
    var vendors = {
        elk: { src: '/static/vendor/elk.bundled.js', global: 'ELK' },
        xlsx: { src: '/static/vendor/xlsx.full.min.js', global: 'XLSX' }
    };

    function loaded(name) {
        if (name === 'elk' && !window.ELK && window.elk) window.ELK = window.elk;
        return window[vendors[name].global];
    }

    window.loadFrontendVendor = function (name) {
        if (!vendors[name]) return Promise.reject(new Error('未知组件: ' + name));
        if (loaded(name)) return Promise.resolve(loaded(name));
        if (pending[name]) return pending[name];
        pending[name] = new Promise(function (resolve, reject) {
            var script = document.createElement('script');
            var timer = setTimeout(fail, 30000);
            function fail() {
                clearTimeout(timer);
                script.onload = script.onerror = null;
                script.remove();
                delete pending[name];
                reject(new Error('组件加载失败，请重试: ' + name));
            }
            script.src = vendors[name].src;
            script.async = true;
            script.onerror = fail;
            script.onload = function () {
                if (!loaded(name)) { fail(); return; }
                clearTimeout(timer);
                script.onload = script.onerror = null;
                resolve(loaded(name));
            };
            document.head.appendChild(script);
        });
        return pending[name];
    };
})();
