/* grokbuild Admin SPA — in-memory admin key, textContent-only DOM */
(function () {
  "use strict";

  var API_BASE = "";

  var state = {
    key: "",
    route: "login",
    system: null,
    settings: null,
    credentials: [],
    credentialQuery: "",
    credentialStatus: "all",
    credentialPage: 1,
    credentialPageSize: 24,
    credentialPagination: null,
    credentialPool: null,
    credentialSearchTimer: null,
    credentialLoadSequence: 0,
    inspectionPollSequence: 0,
    busy: false,
  };

  // ---------- DOM helpers (no innerHTML for untrusted data) ----------

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null && text !== "") node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function show(node, on) {
    if (!node) return;
    node.classList.toggle("hidden", !on);
  }

  function setText(node, text) {
    if (node) node.textContent = text == null ? "" : String(text);
  }

  // ---------- Toast ----------

  function toast(message, kind) {
    var host = $("toast-host");
    if (!host) return;
    var t = el("div", "toast " + (kind || ""));
    t.textContent = message;
    host.appendChild(t);
    setTimeout(function () {
      if (t.parentNode) t.parentNode.removeChild(t);
    }, 3200);
  }

  // ---------- Modal ----------

  function openModal(title, bodyNode, footNodes) {
    var modal = $("modal");
    setText($("modal-title"), title || "对话框");
    var body = $("modal-body");
    clear(body);
    if (bodyNode) body.appendChild(bodyNode);
    var foot = $("modal-foot");
    clear(foot);
    (footNodes || []).forEach(function (n) {
      foot.appendChild(n);
    });
    show(modal, true);
  }

  function closeModal() {
    show($("modal"), false);
    clear($("modal-body"));
    clear($("modal-foot"));
  }

  // ---------- API ----------

  function apiErrorMessage(data, status) {
    if (data && data.error) {
      if (typeof data.error === "string") return data.error;
      if (data.error.message) return data.error.message;
    }
    if (data && data.message) return data.message;
    return "请求失败 HTTP " + status;
  }

  function api(method, path, body) {
    var headers = {
      Accept: "application/json",
    };
    if (state.key) {
      headers.Authorization = "Bearer " + state.key;
    }
    var opts = { method: method, headers: headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = typeof body === "string" ? body : JSON.stringify(body);
    }
    return fetch(API_BASE + path, opts).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            data = { raw: text };
          }
        }
        if (res.status === 401) {
          logout(true);
          var err401 = new Error(apiErrorMessage(data, res.status) || "未授权");
          err401.status = 401;
          throw err401;
        }
        if (!res.ok) {
          var err = new Error(apiErrorMessage(data, res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function apiForm(method, path, form) {
    var headers = { Accept: "application/json" };
    if (state.key) headers.Authorization = "Bearer " + state.key;
    return fetch(API_BASE + path, { method: method, headers: headers, body: form }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            data = { raw: text };
          }
        }
        if (res.status === 401) {
          logout(true);
          throw new Error(apiErrorMessage(data, res.status) || "未授权");
        }
        if (!res.ok) {
          var err = new Error(apiErrorMessage(data, res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  // ---------- Routing ----------

  function parseRoute() {
    var hash = (location.hash || "").replace(/^#\/?/, "");
    var name = (hash.split("?")[0] || "").split("/")[0] || "";
    if (!name) name = state.key ? "credentials" : "login";
    return name;
  }

  function navigate(route) {
    if (!route) route = "credentials";
    location.hash = "#/" + route;
  }

  function requireAuth(route) {
    if (route === "login") return "login";
    if (!state.key) return "login";
    return route;
  }

  function setActiveNav(route) {
    var links = document.querySelectorAll("#main-nav a");
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      a.classList.toggle("active", a.getAttribute("data-route") === route);
    }
  }

  function render() {
    var route = requireAuth(parseRoute());
    state.route = route;

    show($("view-login"), route === "login");
    show($("view-shell"), route !== "login");

    if (route === "login") {
      if (state.key) {
        navigate("credentials");
      }
      return;
    }

    setActiveNav(route);
    show($("page-credentials"), route === "credentials");
    show($("page-clients"), route === "clients");
    show($("page-settings"), route === "settings");
    show($("page-system"), route === "system");
    show($("page-integration"), route === "integration");

    if (route === "credentials") loadCredentials();
    else if (route === "clients") loadClients();
    else if (route === "settings") loadSettings();
    else if (route === "system") loadSystem();
    else if (route === "integration") renderIntegration();
  }

  // ---------- Auth ----------

  function logout(silent) {
    state.key = "";
    state.system = null;
    if (!silent) toast("已退出", "ok");
    navigate("login");
    render();
  }

  function login(key) {
    key = (key || "").trim();
    if (!key) {
      setText($("login-error"), "请输入管理员密钥");
      show($("login-error"), true);
      return Promise.resolve();
    }
    var btn = $("login-submit");
    if (btn) btn.disabled = true;
    show($("login-error"), false);
    var prev = state.key;
    state.key = key;
    return api("GET", "/admin/system")
      .then(function (sys) {
        state.system = sys;
        setText($("shell-version"), (sys && sys.version) || "管理后台");
        toast("登录成功", "ok");
        navigate("credentials");
        render();
      })
      .catch(function (err) {
        state.key = prev;
        setText($("login-error"), err.message || "登录失败");
        show($("login-error"), true);
      })
      .finally(function () {
        if (btn) btn.disabled = false;
      });
  }

  // ---------- Format helpers ----------

  function fmtTime(v) {
    if (!v) return "—";
    try {
      var d = new Date(v);
      if (isNaN(d.getTime())) return String(v);
      return d.toLocaleString();
    } catch (_) {
      return String(v);
    }
  }

  function shortId(id) {
    if (!id) return "—";
    if (id.length <= 12) return id;
    return id.slice(0, 6) + "…" + id.slice(-4);
  }

  function inspectionStatusText(status) {
    var labels = {
      healthy: "健康",
      unauthorized: "认证失效",
      unauthorized_unconfirmed: "待确认的认证失效",
      rate_limited: "触发限流",
      quota_exhausted: "额度耗尽",
      mass_failure_guard: "批量异常保护",
      state_changed: "凭证已变更，结果未应用",
      settings_changed: "巡检设置已变更，结果未应用",
    };
    return labels[status] || status || "未记录";
  }

  // ---------- Credentials ----------

  function loadCredentials() {
    var list = $("cred-list");
    var empty = $("cred-empty");
    if (!list) return;
    clear(list);
    clear($("credential-pagination"));
    show(empty, false);
    if (state.credentialSearchTimer) {
      clearTimeout(state.credentialSearchTimer);
      state.credentialSearchTimer = null;
    }
    var sequence = ++state.credentialLoadSequence;
    list.setAttribute("aria-busy", "true");
    list.appendChild(el("div", "credential-loading", "正在加载账号…"));
    var query = (state.credentialQuery || "").trim();
    var path =
      "/admin/credentials?page=" + encodeURIComponent(state.credentialPage || 1) +
      "&page_size=" + encodeURIComponent(state.credentialPageSize || 24) +
      "&status=" + encodeURIComponent(state.credentialStatus || "all") +
      "&q=" + encodeURIComponent(query);
    api("GET", path)
      .then(function (data) {
        if (sequence !== state.credentialLoadSequence) return;
        state.credentials = (data && data.credentials) || [];
        state.credentialPagination = (data && data.pagination) || null;
        state.credentialPool = (data && data.pool) || null;
        if (state.credentialPagination && state.credentialPagination.page) {
          state.credentialPage = Number(state.credentialPagination.page) || 1;
        }
        if (state.credentialPagination && state.credentialPagination.page_size) {
          state.credentialPageSize = Number(state.credentialPagination.page_size) || 24;
        }
        renderCredentialList();
      })
      .catch(function (err) {
        if (sequence !== state.credentialLoadSequence) return;
        clear(list);
        toast("加载凭证失败: " + err.message, "err");
      })
      .finally(function () {
        if (sequence === state.credentialLoadSequence) list.removeAttribute("aria-busy");
      });
  }

  function renderCredentialList() {
    var list = $("cred-list");
    var empty = $("cred-empty");
    if (!list || !empty) return;
    clear(list);
    var credentials = state.credentials || [];
    var pagination = state.credentialPagination || {};
    var pool = state.credentialPool || {};
    var total = num(pagination.total);
    var page = Math.max(1, num(pagination.page) || 1);
    var pageSize = Math.max(1, num(pagination.page_size) || 24);
    var start = total ? (page - 1) * pageSize + 1 : 0;
    var end = total ? start + credentials.length - 1 : 0;
    show(empty, total === 0);
    var emptyTitle = empty.querySelector("h3");
    if (emptyTitle) {
      setText(
        emptyTitle,
        total === 0 && ((state.credentialQuery || "").trim() || state.credentialStatus !== "all")
          ? "没有匹配的账号"
          : "暂无凭证"
      );
    }
    setText(
      $("credential-pool-summary"),
      "共 " + num(pool.total) + " 个账号，" + num(pool.available) + " 个可用，" + num(pool.cooling) + " 个冷却中；显示 " + start + "-" + end + " / " + total
    );
    var cards = document.createDocumentFragment();
    credentials.forEach(function (c) {
      cards.appendChild(renderCredentialCard(c));
    });
    list.appendChild(cards);
    renderCredentialPagination(pagination);
  }

  function renderCredentialPagination(pagination) {
    var host = $("credential-pagination");
    if (!host) return;
    clear(host);
    var totalPages = num(pagination && pagination.total_pages);
    if (totalPages <= 1) return;
    var page = Math.max(1, num(pagination.page) || 1);
    var previous = el("button", "btn btn-sm", "上一页");
    previous.type = "button";
    previous.disabled = page <= 1;
    previous.addEventListener("click", function () {
      state.credentialPage = page - 1;
      loadCredentials();
    });
    var next = el("button", "btn btn-sm", "下一页");
    next.type = "button";
    next.disabled = page >= totalPages;
    next.addEventListener("click", function () {
      state.credentialPage = page + 1;
      loadCredentials();
    });
    var jump = el("input");
    jump.type = "number";
    jump.min = "1";
    jump.max = String(totalPages);
    jump.value = String(page);
    jump.setAttribute("aria-label", "跳转页码");
    jump.addEventListener("change", function () {
      var target = Math.max(1, Math.min(totalPages, parseInt(jump.value, 10) || page));
      if (target !== page) {
        state.credentialPage = target;
        loadCredentials();
      } else {
        jump.value = String(page);
      }
    });
    host.appendChild(previous);
    host.appendChild(jump);
    host.appendChild(el("span", "muted", "/ " + totalPages + " 页"));
    host.appendChild(next);
  }

  function renderCredentialCard(c) {
    var card = el("article", "card cred-card");
    card.dataset.id = c.id || "";

    var top = el("div", "cred-top");
    var left = el("div");
    var title = el("h3", "cred-title", c.name || c.email || c.id || "（未命名）");
    left.appendChild(title);
    if (c.email && c.email !== c.name) {
      left.appendChild(el("div", "muted", c.email));
    }
    top.appendChild(left);

    var quarantined = c.lifecycle_state === "quarantined";
    var badge = el(
      "span",
      "badge " + (c.enabled ? "badge-ok" : quarantined ? "badge-danger" : "badge-off"),
      c.enabled ? "已启用" : quarantined ? "已隔离" : "已禁用"
    );
    top.appendChild(badge);
    card.appendChild(top);

    var meta = el("div", "cred-meta");
    meta.appendChild(lineMeta("编号", shortId(c.id)));
    meta.appendChild(lineMeta("优先级", String(c.priority != null ? c.priority : 0)));
    meta.appendChild(lineMeta("过期时间", fmtTime(c.expires_at)));
    meta.appendChild(
      lineMeta(
        "出站代理",
        c.proxy_mode === "url" ? c.proxy_url || "已配置" : c.proxy_mode === "direct" ? "直连" : "继承全局"
      )
    );
    if (c.disable_reason) meta.appendChild(lineMeta("停用原因", c.disable_reason));
    if (c.quarantined_at) meta.appendChild(lineMeta("隔离时间", fmtTime(c.quarantined_at)));
    meta.appendChild(
      lineMeta(
        "令牌",
        (c.has_access_token ? "访问令牌" : "—") +
          " / " +
          (c.has_refresh_token ? "刷新令牌" : "—")
      )
    );
    if (c.failure_count) {
      meta.appendChild(lineMeta("失败次数", String(c.failure_count)));
    }
    if (c.last_error) {
      var errLine = el("div");
      errLine.appendChild(el("span", "badge badge-danger", "错误"));
      errLine.appendChild(document.createTextNode(" "));
      errLine.appendChild(el("span", "", c.last_error));
      meta.appendChild(errLine);
    }
    if (c.cooldown_until) {
      meta.appendChild(lineMeta("冷却至", fmtTime(c.cooldown_until)));
    }
    if (
      c.rate_limit_remaining_requests != null ||
      c.rate_limit_limit_requests != null ||
      c.rate_limit_remaining_tokens != null ||
      c.rate_limit_limit_tokens != null
    ) {
      var reqPart =
        (c.rate_limit_remaining_requests != null ? String(c.rate_limit_remaining_requests) : "—") +
        " / " +
        (c.rate_limit_limit_requests != null ? String(c.rate_limit_limit_requests) : "—");
      var tokPart =
        (c.rate_limit_remaining_tokens != null ? String(c.rate_limit_remaining_tokens) : "—") +
        " / " +
        (c.rate_limit_limit_tokens != null ? String(c.rate_limit_limit_tokens) : "—");
      meta.appendChild(lineMeta("聊天额度(请求)", reqPart));
      meta.appendChild(lineMeta("聊天额度(Token)", tokPart));
      if (c.rate_limit_observed_at) {
        meta.appendChild(lineMeta("额度采样", fmtTime(c.rate_limit_observed_at)));
      }
    }
    if (c.last_inspection_at || c.last_inspection_status || c.last_inspection_error) {
      meta.appendChild(lineMeta("最近巡检", fmtTime(c.last_inspection_at)));
      meta.appendChild(lineMeta("巡检结果", inspectionStatusText(c.last_inspection_status)));
      if (c.last_inspection_error) {
        meta.appendChild(lineMeta("巡检详情", c.last_inspection_error));
      }
    }
    if (c.access_token) {
      meta.appendChild(lineMeta("访问令牌(脱敏)", c.access_token));
    }
    var usageBox = el("div", "usage-box");
    usageBox.appendChild(el("div", "muted", "额度在查看账单时按需加载"));
    meta.appendChild(usageBox);
    card.appendChild(meta);

    var prioRow = el("div", "priority-row");
    prioRow.appendChild(el("span", "label", "优先级"));
    var prioInput = el("input");
    prioInput.type = "number";
    prioInput.value = String(c.priority != null ? c.priority : 0);
    prioInput.setAttribute("aria-label", "优先级");
    var prioBtn = el("button", "btn btn-sm", "保存");
    prioBtn.type = "button";
    prioBtn.addEventListener("click", function () {
      var n = parseInt(prioInput.value, 10);
      if (isNaN(n)) {
        toast("优先级必须是数字", "err");
        return;
      }
      prioBtn.disabled = true;
      // PUT /admin/credentials/{id}/priority  body: {"priority":n}
      api("PUT", "/admin/credentials/" + encodeURIComponent(c.id) + "/priority", {
        priority: n,
      })
        .then(function () {
          toast("优先级已更新", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("更新失败: " + err.message, "err");
        })
        .finally(function () {
          prioBtn.disabled = false;
        });
    });
    prioRow.appendChild(prioInput);
    prioRow.appendChild(prioBtn);
    card.appendChild(prioRow);

    var actions = el("div", "cred-actions");

    var toggle = el("button", "btn btn-sm", c.enabled ? "禁用" : "启用");
    toggle.type = "button";
    toggle.addEventListener("click", function () {
      toggle.disabled = true;
      // POST /admin/credentials/{id}/disable  body: {"enabled": true|false}
      api("POST", "/admin/credentials/" + encodeURIComponent(c.id) + "/disable", {
        enabled: !c.enabled,
      })
        .then(function () {
          toast(c.enabled ? "已禁用" : "已启用", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("切换失败: " + err.message, "err");
        })
        .finally(function () {
          toggle.disabled = false;
        });
    });
    actions.appendChild(toggle);

    var refresh = el("button", "btn btn-sm", "刷新令牌");
    refresh.type = "button";
    refresh.addEventListener("click", function () {
      refresh.disabled = true;
      api("POST", "/admin/credentials/" + encodeURIComponent(c.id) + "/refresh")
        .then(function () {
          toast("令牌已刷新", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("刷新令牌失败: " + err.message, "err");
        })
        .finally(function () {
          refresh.disabled = false;
        });
    });
    actions.appendChild(refresh);

    var proxyBtn = el("button", "btn btn-sm", "代理");
    proxyBtn.type = "button";
    proxyBtn.addEventListener("click", function () {
      showCredentialProxy(c);
    });
    actions.appendChild(proxyBtn);

    var billing = el("button", "btn btn-sm", "账单");
    billing.type = "button";
    billing.addEventListener("click", function () {
      showBilling(c);
    });
    actions.appendChild(billing);

    var del = el("button", "btn btn-sm btn-danger", "删除");
    del.type = "button";
    del.addEventListener("click", function () {
      if (!confirm("确认删除凭证 " + (c.name || c.id) + " ?")) return;
      del.disabled = true;
      api("DELETE", "/admin/credentials/" + encodeURIComponent(c.id))
        .then(function () {
          toast("已删除", "ok");
          loadCredentials();
        })
        .catch(function (err) {
          toast("删除失败: " + err.message, "err");
        })
        .finally(function () {
          del.disabled = false;
        });
    });
    actions.appendChild(del);

    card.appendChild(actions);
    return card;
  }

  function showCredentialProxy(c) {
    var body = el("div", "stack");
    var modeField = el("label", "field");
    modeField.appendChild(el("span", "label", "代理模式"));
    var mode = el("select");
    [
      ["inherit", "继承全局"],
      ["direct", "强制直连"],
      ["url", "自定义代理 URL"],
    ].forEach(function (value) {
      var option = el("option", "", value[1]);
      option.value = value[0];
      option.selected = (c.proxy_mode || "inherit") === value[0];
      mode.appendChild(option);
    });
    modeField.appendChild(mode);
    body.appendChild(modeField);
    var urlField = el("label", "field");
    urlField.appendChild(el("span", "label", "代理 URL"));
    var proxyURL = el("input");
    proxyURL.type = "password";
    proxyURL.placeholder = "http://user:pass@host:port 或 socks5h://host:port";
    urlField.appendChild(proxyURL);
    body.appendChild(urlField);
    body.appendChild(el("p", "muted", "现有代理密码不会回显；切换为自定义 URL 时需重新完整输入。"));
    function sync() {
      proxyURL.disabled = mode.value !== "url";
    }
    mode.addEventListener("change", sync);
    sync();

    var cancel = el("button", "btn", "取消");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    var save = el("button", "btn btn-primary", "保存");
    save.type = "button";
    save.addEventListener("click", function () {
      if (mode.value === "url" && !(proxyURL.value || "").trim()) {
        toast("请输入完整代理 URL", "err");
        return;
      }
      save.disabled = true;
      api("PUT", "/admin/credentials/" + encodeURIComponent(c.id) + "/proxy", {
        mode: mode.value,
        url: (proxyURL.value || "").trim(),
      })
        .then(function () {
          proxyURL.value = "";
          toast("凭证代理已更新", "ok");
          closeModal();
          loadCredentials();
        })
        .catch(function (err) {
          toast("代理设置失败: " + err.message, "err");
        })
        .finally(function () {
          save.disabled = false;
        });
    });
    openModal("凭证代理 · " + (c.name || c.email || shortId(c.id)), body, [cancel, save]);
  }

  function lineMeta(label, value) {
    var row = el("div");
    row.appendChild(el("strong", "", label + ": "));
    row.appendChild(el("code", "", value));
    return row;
  }

  function showBilling(c) {
    var body = el("div", "stack");
    body.appendChild(el("p", "muted", "加载账单…"));
    var closeBtn = el("button", "btn", "关闭");
    closeBtn.type = "button";
    closeBtn.addEventListener("click", closeModal);
    var reloadBtn = el("button", "btn btn-primary", "刷新");
    reloadBtn.type = "button";
    openModal("账单 · " + (c.name || c.email || shortId(c.id)), body, [
      reloadBtn,
      closeBtn,
    ]);

    function load() {
      clear(body);
      body.appendChild(el("p", "muted", "加载账单…"));
      reloadBtn.disabled = true;
      api("GET", "/admin/credentials/" + encodeURIComponent(c.id) + "/billing")
        .then(function (snap) {
          clear(body);
          body.appendChild(renderBillingDashboard(snap));
          // Raw JSON is optional debug only — collapsed by default.
          var details = el("details", "raw-details");
          var summary = el("summary", "", "调试：原始 JSON（默认折叠）");
          details.appendChild(summary);
          var pre = el("pre", "code");
          pre.textContent = JSON.stringify(snap, null, 2);
          details.appendChild(pre);
          body.appendChild(details);
        })
        .catch(function (err) {
          clear(body);
          body.appendChild(el("p", "error", err.message || "账单加载失败"));
        })
        .finally(function () {
          reloadBtn.disabled = false;
        });
    }
    reloadBtn.addEventListener("click", load);
    load();
  }

  function parseUsage(snap) {
    var m = (snap && snap.monthly) || {};
    var w = (snap && snap.weekly) || {};
    var limit = optionalNum(m.monthlyLimit);
    var used = optionalNum(m.used);
    var rem = limit != null && used != null ? Math.max(0, limit - used) : null;
    var monthPct = limit != null && limit > 0 && used != null ? (used / limit) * 100 : null;
    var weekPct = optionalNum(w.creditUsagePercent);
    return {
      limit: limit,
      used: used,
      rem: rem,
      monthPct: monthPct,
      weekPct: weekPct,
      monthLabel:
        limit != null && limit > 0 && used != null
          ? fmtNum(used) + " / " + fmtNum(limit) + "（剩 " + fmtNum(rem) + "）"
          : used != null
            ? "已用 " + fmtNum(used) + "（无限额字段）"
            : "未报告",
      weekLabel: weekPct != null ? weekPct.toFixed(1) + "%" : "未报告",
      monthTone: monthPct != null ? toneFromPct(monthPct) : "neutral",
      weekTone: weekPct != null ? toneFromPct(weekPct) : "neutral",
      period:
        (m.billingPeriodStart || "") && (m.billingPeriodEnd || "")
          ? fmtDay(m.billingPeriodStart) + " → " + fmtDay(m.billingPeriodEnd)
          : m.billingPeriodEnd
            ? "至 " + fmtDay(m.billingPeriodEnd)
            : "",
      weekEnd: w.billingPeriodEnd ? fmtDay(w.billingPeriodEnd) : "",
      products: parseProductUsage(w.productUsage),
    };
  }

  function parseProductUsage(raw) {
    if (!raw) return [];
    try {
      var arr = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (!Array.isArray(arr)) return [];
      return arr
        .map(function (p) {
          return {
            name: p.product || p.name || "?",
            pct: optionalNum(p.usagePercent != null ? p.usagePercent : p.usage_percent),
          };
        })
        .filter(function (p) {
          return p.name;
        });
    } catch (_) {
      return [];
    }
  }

  function renderBillingDashboard(snap) {
    var u = parseUsage(snap);
    var build = (snap && snap.grok_build) || {};
    var wrap = el("div", "stack billing-dash");

    var hero = el("div", "billing-hero");
    hero.appendChild(el("div", "billing-hero-title", "Grok Build 额度"));
    hero.appendChild(
      el(
        "div",
        "billing-hero-value",
        build.reported && build.shared_weekly_usage_percent != null
          ? num(build.shared_weekly_usage_percent).toFixed(1) + "% 已用"
          : "未报告"
      )
    );
    hero.appendChild(
      el(
        "div",
        "muted",
        build.grok_build_contribution_percent != null
          ? "Grok Build 对共享周额度池的消耗贡献 " + num(build.grok_build_contribution_percent).toFixed(1) + "%（不是独立上限）"
          : "共享周额度；上游未单独报告 Grok Build 消耗贡献"
      )
    );
    wrap.appendChild(hero);

    if (build.reported && build.shared_weekly_usage_percent != null) {
      wrap.appendChild(usageBar("共享周额度", num(build.shared_weekly_usage_percent), num(build.shared_weekly_usage_percent).toFixed(1) + "%", toneFromPct(num(build.shared_weekly_usage_percent))));
    }

    var diagnostics = el("details", "raw-details");
    diagnostics.appendChild(el("summary", "", "诊断：月度/API 与产品明细"));
    var grid = el("div", "billing-grid");
    grid.appendChild(statCard("月已用", u.used != null ? fmtNum(u.used) : "未报告"));
    grid.appendChild(statCard("月上限", u.limit != null ? fmtNum(u.limit) : "未报告"));
    grid.appendChild(statCard("月剩余", u.rem != null ? fmtNum(u.rem) : "未报告"));
    grid.appendChild(statCard("周用量", u.weekPct != null ? u.weekPct.toFixed(1) + "%" : "未报告"));
    diagnostics.appendChild(grid);

    if (u.period) {
      diagnostics.appendChild(lineMeta("月账期", u.period));
    }
    if (u.weekEnd) {
      diagnostics.appendChild(lineMeta("周账期结束", u.weekEnd));
    }

    if (u.products.length) {
      diagnostics.appendChild(el("div", "section-label", "产品用量"));
      u.products.forEach(function (p) {
        diagnostics.appendChild(
          usageBar(
            p.name,
            p.pct != null ? p.pct : 0,
            p.pct != null ? p.pct.toFixed(1) + "%" : "未报告",
            p.pct != null ? toneFromPct(p.pct) : "neutral"
          )
        );
      });
    }
	if (snap && snap.monthly_error) diagnostics.appendChild(el("p", "error", "月度接口: " + snap.monthly_error));
	if (snap && snap.weekly_error) diagnostics.appendChild(el("p", "error", "周额度接口: " + snap.weekly_error));
	wrap.appendChild(diagnostics);

    if (!build.reported) {
      wrap.appendChild(
        el("p", "muted", "Grok Build 共享周额度：未报告。月度/API 数据仍可在诊断区查看。")
      );
    } else if (num(build.shared_weekly_usage_percent) >= 100) {
      wrap.appendChild(
        el("p", "error", "周额度已用尽（上游可能返回 402 账单错误）。")
      );
    } else if (u.monthPct != null && u.monthPct >= 95) {
      wrap.appendChild(el("p", "error", "月额度即将用尽，请留意切换账号。"));
    }

    return wrap;
  }

  function usageBar(label, pct, detail, tone) {
    var box = el("div", "usage-bar-wrap");
    var head = el("div", "usage-bar-head");
    head.appendChild(el("span", "", label));
    head.appendChild(el("span", "muted", detail || ""));
    box.appendChild(head);
    var track = el("div", "usage-track");
    var fill = el("div", "usage-fill " + (tone || "tone-ok"));
    var width = Math.max(0, Math.min(100, Number(pct) || 0));
    fill.style.width = width.toFixed(1) + "%";
    track.appendChild(fill);
    box.appendChild(track);
    return box;
  }

  function statCard(label, value) {
    var card = el("div", "stat-card");
    card.appendChild(el("div", "muted", label));
    card.appendChild(el("div", "stat-value", value));
    return card;
  }

  function num(v) {
    var n = Number(v);
    return isFinite(n) ? n : 0;
  }

  function optionalNum(v) {
    if (v == null || v === "") return null;
    var n = Number(v);
    return isFinite(n) ? n : null;
  }

  function fmtNum(n) {
    n = num(n);
    try {
      return n.toLocaleString("zh-CN", { maximumFractionDigits: 1 });
    } catch (_) {
      return String(n);
    }
  }

  function fmtDay(iso) {
    if (!iso) return "";
    // Keep date part readable without forcing timezone conversion surprises.
    var s = String(iso);
    if (s.length >= 10) return s.slice(0, 10);
    return s;
  }

  function toneFromPct(pct) {
    pct = num(pct);
    if (pct >= 95) return "tone-danger";
    if (pct >= 70) return "tone-warn";
    return "tone-ok";
  }

  function importDefaultGrok() {
    // POST /admin/credentials/import-grok with empty/{} body → default ~/.grok path
    api("POST", "/admin/credentials/import-grok", {})
      .then(function (data) {
        var n = (data && data.imported) || 0;
        toast("已导入 " + n + " 条凭证", "ok");
        loadCredentials();
      })
      .catch(function (err) {
        toast("导入失败: " + err.message, "err");
      });
  }

  function startDeviceLogin() {
    api("POST", "/admin/oauth/device/start", {})
      .then(function (data) {
        var body = el("div", "stack");
        body.appendChild(el("p", "muted", "在 xAI 页面完成授权，此窗口会自动检测结果。"));
        var code = el("code", "code-block", data.user_code || "");
        body.appendChild(code);
        var link = el("a", "btn btn-primary", "打开授权页面");
        link.href = data.verification_uri_complete || data.verification_uri || "#";
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        body.appendChild(link);
        var status = el("p", "muted", "等待授权…");
        status.id = "device-login-status";
        body.appendChild(status);
        var cancel = el("button", "btn", "取消");
        cancel.type = "button";
        cancel.addEventListener("click", closeModal);
        openModal("浏览器登录", body, [cancel]);

        var interval = Math.max(1, Number(data.interval) || 5) * 1000;
        function poll() {
          if (!$("device-login-status")) return;
          api("POST", "/admin/oauth/device/poll", { session_id: data.session_id })
            .then(function (result) {
              if (result && result.status === "authorized") {
                toast("账号授权成功", "ok");
                closeModal();
                loadCredentials();
                return;
              }
              setText($("device-login-status"), "等待授权…");
              var delay = Math.max(1, Number(result && result.retry_after) || interval / 1000) * 1000;
              setTimeout(poll, delay);
            })
            .catch(function (err) {
              if (err.status === 429) {
                var retry = Number(err.data && err.data.retry_after) || interval / 1000;
                setTimeout(poll, Math.max(1, retry) * 1000);
                return;
              }
              setText($("device-login-status"), "授权失败: " + err.message);
            });
        }
        setTimeout(poll, interval);
      })
      .catch(function (err) {
        toast("启动浏览器登录失败: " + err.message, "err");
      });
  }

  function openImportRawModal() {
    var body = el("div", "stack");
    body.appendChild(
      el(
        "p",
        "muted",
        "上传多个 Grok / CPA JSON 或 SSO 文件，也可直接粘贴内容。原始文本会直接发送，重复 JSON 顶层名称不会在浏览器中被覆盖。"
      )
    );
    var formatField = el("label", "field");
    formatField.appendChild(el("span", "label", "内容类型"));
    var format = el("select");
    [
      ["auto", "自动识别"],
      ["json", "Grok / CPA JSON"],
      ["sso", "SSO 文本 / JSON"],
    ].forEach(function (option) {
      var node = el("option", "", option[1]);
      node.value = option[0];
      format.appendChild(node);
    });
    formatField.appendChild(format);
    body.appendChild(formatField);

    var fileField = el("label", "field");
    fileField.appendChild(el("span", "label", "选择文件或目录（可多选）"));
    var fileInput = el("input");
    fileInput.type = "file";
    fileInput.multiple = true;
    fileInput.setAttribute("webkitdirectory", "");
    fileInput.setAttribute("directory", "");
    fileInput.accept = ".json,.txt,.sso,application/json,text/plain";
    fileField.appendChild(fileInput);
    body.appendChild(fileField);

    body.appendChild(el("div", "muted", "或粘贴内容"));
    var ta = el("textarea");
    ta.placeholder = "auth.json / CPA xAI JSON / 每行一个 SSO";
    body.appendChild(ta);
    var status = el("div", "muted");
    body.appendChild(status);
    var importDetails = el("pre", "code");
    importDetails.style.display = "none";
    body.appendChild(importDetails);

    var cancel = el("button", "btn", "取消");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);

    var ok = el("button", "btn btn-primary", "导入");
    ok.type = "button";
    ok.addEventListener("click", function () {
      var rawText = (ta.value || "").trim();
      var selected = fileInput.files || [];
      if (!rawText && !selected.length) {
        toast("请选择文件或粘贴内容", "err");
        return;
      }
      ok.disabled = true;
      setText(status, "正在创建导入任务…");
      var request;
      if (selected.length) {
        var form = new FormData();
        form.append("format", format.value || "auto");
        for (var i = 0; i < selected.length; i++) form.append("files", selected[i], selected[i].name);
        if (rawText) {
          form.append("files", new Blob([rawText], { type: "text/plain" }), "pasted.txt");
        }
        request = apiForm("POST", "/admin/import-jobs", form);
      } else {
        request = api("POST", "/admin/import-jobs", {
          name: format.value === "json" ? "pasted.json" : "pasted.txt",
          format: format.value || "auto",
          text: rawText,
        });
      }
      request
        .then(function (job) {
          setText(status, "任务已创建，正在解析与写入…");
          return pollImportJob(job.id, status, importDetails);
        })
        .then(function (job) {
          var imported = num(job.created) + num(job.updated);
          var message =
            "导入完成：" + imported + " 条（新增 " + num(job.created) + "，更新 " + num(job.updated) +
            "，跳过 " + num(job.skipped) + "）";
          if (job.failed) message += "，失败 " + job.failed;
          if (job.warning_count) message += "，警告 " + job.warning_count;
          toast(message, job.failed ? "err" : "ok");
          ta.value = "";
          fileInput.value = "";
          loadCredentials();
        })
        .catch(function (err) {
          toast("导入失败: " + err.message, "err");
          setText(status, "导入失败: " + err.message);
        })
        .finally(function () {
          ok.disabled = false;
        });
    });

    openModal("批量导入凭证", body, [cancel, ok]);
  }

  function pollImportJob(id, statusNode, detailsNode) {
    return new Promise(function (resolve, reject) {
      function poll() {
        api("GET", "/admin/import-jobs/" + encodeURIComponent(id))
          .then(function (job) {
            setText(
              statusNode,
              "状态：" + (job.status || "unknown") +
                " · 文件 " + num(job.files_processed) + "/" + num(job.files_total) +
                " · 条目 " + num(job.processed) + "/" + num(job.total) +
                " · 新增 " + num(job.created) +
                " · 更新 " + num(job.updated) +
                " · 跳过 " + num(job.skipped) +
                " · 失败 " + num(job.failed)
            );
            renderImportJobDetails(job, detailsNode);
            if (job.status === "completed" || job.status === "partial" || job.status === "failed") {
              if (job.status === "failed" && !job.created && !job.updated) {
                var detail = job.error || ((job.results || [])[0] || {}).error || "导入任务失败";
                reject(new Error(detail));
                return;
              }
              resolve(job);
              return;
            }
            setTimeout(poll, 500);
          })
          .catch(reject);
      }
      poll();
    });
  }

  function renderImportJobDetails(job, node) {
    if (!node) return;
    var lines = [];
    (job.files || []).forEach(function (file) {
      lines.push(
        (file.source || "file") + " · " + (file.name || "未命名") + " · " + (file.status || "unknown") +
          " · " + num(file.processed) + "/" + num(file.total)
      );
      (file.warnings || []).forEach(function (warning) {
        lines.push("  警告 [" + (warning.field || "unknown") + "] " + (warning.message || ""));
      });
      (file.results || []).forEach(function (result) {
        var line = "  " + (result.source || "entry") + " · " + (result.status || "unknown");
        if (result.error) line += " · " + result.error;
        lines.push(line);
        (result.warnings || []).forEach(function (warning) {
          lines.push("    警告 [" + (warning.field || "unknown") + "] " + (warning.message || ""));
        });
      });
    });
    node.style.display = lines.length ? "block" : "none";
    setText(node, lines.join("\n"));
  }

  // ---------- Clients ----------

  function loadClients() {
    var wrap = $("client-list");
    var empty = $("client-empty");
    if (!wrap) return;
    clear(wrap);
    show(empty, false);
    show(wrap, true);
    api("GET", "/admin/clients")
      .then(function (data) {
        var clients = (data && data.clients) || [];
        if (!clients.length) {
          show(empty, true);
          show(wrap, false);
          return;
        }
        wrap.appendChild(renderClientTable(clients));
      })
      .catch(function (err) {
        toast("加载客户端失败: " + err.message, "err");
      });
  }

  function renderClientTable(clients) {
    var table = el("table");
    var thead = el("thead");
    var hr = el("tr");
    ["名称", "编号", "前缀", "创建时间", "状态", ""].forEach(function (h) {
      hr.appendChild(el("th", "", h));
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el("tbody");
    clients.forEach(function (c) {
      var tr = el("tr");
      tr.appendChild(el("td", "", c.name || "—"));
      var idTd = el("td");
      idTd.appendChild(el("code", "", shortId(c.id)));
      tr.appendChild(idTd);
      var prefTd = el("td");
      prefTd.appendChild(el("code", "", c.prefix || "—"));
      tr.appendChild(prefTd);
      tr.appendChild(el("td", "", fmtTime(c.created_at)));
      var st = el("td");
      st.appendChild(
        el(
          "span",
          "badge " + (c.disabled ? "badge-off" : "badge-ok"),
          c.disabled ? "已停用" : "可用"
        )
      );
      tr.appendChild(st);

      var act = el("td");
      var del = el("button", "btn btn-sm btn-danger", "删除");
      del.type = "button";
      del.addEventListener("click", function () {
        if (!confirm("确认吊销客户端密钥 " + (c.name || c.id) + " ？")) return;
        del.disabled = true;
        api("DELETE", "/admin/clients/" + encodeURIComponent(c.id))
          .then(function () {
            toast("已删除客户端密钥", "ok");
            loadClients();
          })
          .catch(function (err) {
            toast("删除失败: " + err.message, "err");
          })
          .finally(function () {
            del.disabled = false;
          });
      });
      act.appendChild(del);
      tr.appendChild(act);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function openCreateClientModal() {
    var body = el("div", "stack");
    var field = el("label", "field");
    field.appendChild(el("span", "label", "名称（可选）"));
    var input = el("input");
    input.type = "text";
    input.placeholder = "例如：claude-code-本机";
    field.appendChild(input);
    body.appendChild(field);

    var cancel = el("button", "btn", "取消");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);

    var ok = el("button", "btn btn-primary", "创建");
    ok.type = "button";
    ok.addEventListener("click", function () {
      ok.disabled = true;
      api("POST", "/admin/clients", { name: (input.value || "").trim() })
        .then(function (data) {
          var plain = (data && (data.plaintext || data.api_key)) || "";
          showOncePlaintext(plain, data && data.client);
          loadClients();
        })
        .catch(function (err) {
          toast("创建失败: " + err.message, "err");
        })
        .finally(function () {
          ok.disabled = false;
        });
    });

    openModal("创建客户端密钥", body, [cancel, ok]);
  }

  function showOncePlaintext(plain, client) {
    var body = el("div", "stack");
    body.appendChild(
      el(
        "div",
        "warn-note",
        "明文 API Key 仅此一次展示，关闭后无法再次查看。请立即复制保存。"
      )
    );
    if (client && client.name) {
      body.appendChild(el("div", "muted", "名称: " + client.name));
    }
    body.appendChild(el("div", "plaintext-box", plain || "（空）"));

    var copy = el("button", "btn btn-primary", "复制");
    copy.type = "button";
    copy.addEventListener("click", function () {
      copyText(plain).then(
        function () {
          toast("已复制", "ok");
        },
        function () {
          toast("复制失败，请手动选择", "err");
        }
      );
    });
    var close = el("button", "btn", "我已保存");
    close.type = "button";
    close.addEventListener("click", closeModal);
    openModal("客户端密钥", body, [copy, close]);
  }

  // ---------- Runtime settings ----------

  function loadSettings() {
    var host = $("settings-body");
    if (!host) return;
    clear(host);
    host.appendChild(el("p", "muted", "加载运行设置…"));
    api("GET", "/admin/settings")
      .then(function (settings) {
        state.settings = settings;
        clear(host);
        host.appendChild(renderSettings(settings || {}));
      })
      .catch(function (err) {
        clear(host);
        host.appendChild(el("p", "error", "设置加载失败: " + err.message));
      });
  }

  function renderSettings(settings) {
    var wrap = el("div", "stack");
    var globalProxy = settings.global_proxy || {};
    var converter = settings.sso_converter || {};
    var notifications = settings.notifications || {};
    var inspection = settings.inspection || {};

    wrap.appendChild(el("h3", "", "全局出站代理"));
    var proxyMode = settingSelect(
      "代理模式",
      [
        ["environment", "读取 HTTP(S)_PROXY 环境变量"],
        ["direct", "强制直连"],
        ["url", "固定代理 URL"],
      ],
      globalProxy.mode || "environment"
    );
    wrap.appendChild(proxyMode.field);
    if (globalProxy.url) wrap.appendChild(el("p", "muted", "当前：" + globalProxy.url));
    var proxyURL = settingInput(
      "新代理 URL",
      "password",
      "http://user:pass@host:port 或 socks5h://host:port"
    );
    wrap.appendChild(proxyURL.field);

    wrap.appendChild(el("h3", "", "SSO 转换服务"));
    var converterEnabled = settingCheckbox("启用 SSO 文件转换", !!converter.enabled);
    var converterEndpoint = settingInput("服务端点", "url", "https://converter.example");
    converterEndpoint.input.value = converter.endpoint || "";
    var converterKey = settingInput("API Key（留空保持不变）", "password", "转换服务 API Key");
    var converterClear = settingCheckbox("清除已保存的 API Key", false);
    var converterInsecure = settingCheckbox(
      "允许明文 HTTP（仅可信容器网络）",
      !!converter.allow_insecure_http
    );
    var converterTimeout = settingInput("转换超时（秒）", "number");
    converterTimeout.input.value = converter.timeout_sec || 600;
    var converterBatch = settingInput("单批最大 SSO 数", "number");
    converterBatch.input.value = converter.max_batch || 50;
    [
      converterEnabled,
      converterEndpoint,
      converterKey,
      converterClear,
      converterInsecure,
      converterTimeout,
      converterBatch,
    ].forEach(function (item) {
      wrap.appendChild(item.field);
    });
    wrap.appendChild(
      el(
        "p",
        "muted",
        converter.api_key_configured ? "API Key 已配置（不会回显）" : "尚未配置 API Key"
      )
    );

    wrap.appendChild(el("h3", "", "飞书通知"));
    var feishuWebhook = settingInput("Webhook 地址（留空保持不变）", "password", "https://open.feishu.cn/open-apis/bot/v2/hook/...");
    var clearFeishuWebhook = settingCheckbox("清除已保存的 Webhook", false);
    wrap.appendChild(feishuWebhook.field);
    wrap.appendChild(clearFeishuWebhook.field);
    wrap.appendChild(el("p", "muted", notifications.feishu_webhook_configured ? "Webhook 已配置（不会回显）；巡检完成后自动通知。" : "未配置飞书 Webhook。"));

    wrap.appendChild(el("h3", "", "凭证自动巡检"));
    var inspectEnabled = settingCheckbox("启用定时巡检", !!inspection.enabled);
    var inspectInterval = settingInput("巡检间隔（秒）", "number");
    inspectInterval.input.value = inspection.interval_sec || 3600;
    var inspectTimeout = settingInput("单账号超时（秒）", "number");
    inspectTimeout.input.value = inspection.timeout_sec || 30;
    var inspectConcurrency = settingInput("并发数", "number");
    inspectConcurrency.input.value = inspection.concurrency || 2;
    var inspectConfirm = settingInput("连续 401 确认次数", "number");
    inspectConfirm.input.value = inspection.confirm_unauthorized || 2;
    var inspectPurge = settingInput("隔离后自动删除（秒，0 表示不删除）", "number");
    inspectPurge.input.value = inspection.purge_after_sec || 0;
    var inspectBatch = settingInput("每轮最多检测账号数", "number");
    inspectBatch.input.value = inspection.max_credentials_per_run || 100;
    var inspectSkipRecent = settingInput("跳过近期成功账号（秒）", "number");
    inspectSkipRecent.input.value = inspection.skip_recent_success_sec || 900;
    [
      inspectEnabled,
      inspectInterval,
      inspectTimeout,
      inspectConcurrency,
      inspectConfirm,
      inspectPurge,
      inspectBatch,
      inspectSkipRecent,
    ].forEach(function (item) {
      wrap.appendChild(item.field);
    });
    wrap.appendChild(el("p", "muted", "每轮按最久未检测账号优先；401 经刷新复核后隔离，429 只进入冷却。"));
    var inspectionStatus = el("p", "muted", "巡检状态加载中…");
    wrap.appendChild(inspectionStatus);
    var inspectionPollSequence = ++state.inspectionPollSequence;
    function showInspectionSummary(prefix, summary) {
      return prefix + "已检测 " + num(summary.inspected) +
        " · 跳过 " + num(summary.skipped) +
        " · 正常 " + num(summary.healthy) +
        " · 隔离 " + num(summary.quarantined) +
        " · 限流/额度 " + num(summary.rate_limited) +
        " · 错误 " + num(summary.errors) +
        (summary.mass_failure_guard ? " · 已触发批量故障保护" : "");
    }
    function refreshInspectionStatus() {
      api("GET", "/admin/inspection")
        .then(function (data) {
          if (inspectionPollSequence !== state.inspectionPollSequence) return;
        if (data.running) {
            var progress = data.progress || {};
            setText(
              inspectionStatus,
              "巡检中：" + num(progress.completed) + "/" + num(progress.scheduled) +
                " · 候选 " + num(progress.eligible) +
                " · 跳过 " + num(progress.skipped) +
                " · 正常 " + num(progress.healthy) +
                " · 限流/额度 " + num(progress.rate_limited) +
                " · 错误 " + num(progress.errors)
            );
            setTimeout(refreshInspectionStatus, 2000);
        } else if (data.has_run && data.last) {
            setText(inspectionStatus, showInspectionSummary("上次巡检（" + fmtTime(data.last.finished_at) + "）：", data.last));
        } else {
            setText(inspectionStatus, "尚未执行巡检（当前每轮最多检测 " + inspectBatch.input.value + " 个账号）");
        }
        })
        .catch(function () {
          if (inspectionPollSequence === state.inspectionPollSequence) {
            setText(inspectionStatus, "巡检状态不可用");
          }
        });
    }
    refreshInspectionStatus();
    var runInspection = el("button", "btn", "立即巡检");
    runInspection.type = "button";
    runInspection.addEventListener("click", function () {
      runInspection.disabled = true;
      setText(inspectionStatus, "正在巡检，请稍候…");
      api("POST", "/admin/inspection/run")
        .then(function (summary) {
          if (summary && summary.started) {
            setText(inspectionStatus, "巡检已启动，正在获取进度…");
            refreshInspectionStatus();
            return;
          }
          setText(
            inspectionStatus,
            showInspectionSummary("巡检完成：", summary)
          );
          loadCredentials();
        })
        .catch(function (err) {
          setText(inspectionStatus, "巡检失败: " + err.message);
        })
        .finally(function () {
          runInspection.disabled = false;
        });
    });
    wrap.appendChild(runInspection);

    var save = el("button", "btn btn-primary", "保存运行设置");
    save.type = "button";
    save.addEventListener("click", function () {
      var payload = {};
      var nextMode = proxyMode.input.value;
      var nextURL = (proxyURL.input.value || "").trim();
      if (nextMode !== (globalProxy.mode || "environment") || nextURL) {
        if (nextMode === "url" && !nextURL) {
          toast("切换固定代理时必须输入完整代理 URL", "err");
          return;
        }
        payload.global_proxy = { mode: nextMode, url: nextURL };
      }
      payload.sso_converter = {
        enabled: converterEnabled.input.checked,
        allow_insecure_http: converterInsecure.input.checked,
        timeout_sec: parseInt(converterTimeout.input.value, 10),
        max_batch: parseInt(converterBatch.input.value, 10),
        clear_api_key: converterClear.input.checked,
      };
      if ((converterEndpoint.input.value || "").trim()) {
        payload.sso_converter.endpoint = converterEndpoint.input.value.trim();
      }
      if ((converterKey.input.value || "").trim()) {
        payload.sso_converter.api_key = converterKey.input.value.trim();
      }
      payload.notifications = { clear_feishu_webhook: clearFeishuWebhook.input.checked };
      if ((feishuWebhook.input.value || "").trim()) {
        payload.notifications.feishu_webhook_url = feishuWebhook.input.value.trim();
      }
      payload.inspection = Object.assign({}, inspection, {
        enabled: inspectEnabled.input.checked,
        interval_sec: parseInt(inspectInterval.input.value, 10),
        timeout_sec: parseInt(inspectTimeout.input.value, 10),
        concurrency: parseInt(inspectConcurrency.input.value, 10),
        confirm_unauthorized: parseInt(inspectConfirm.input.value, 10),
        purge_after_sec: parseInt(inspectPurge.input.value, 10),
        max_credentials_per_run: parseInt(inspectBatch.input.value, 10),
        skip_recent_success_sec: parseInt(inspectSkipRecent.input.value, 10),
      });
      save.disabled = true;
      api("PUT", "/admin/settings", payload)
        .then(function () {
          proxyURL.input.value = "";
          converterKey.input.value = "";
          toast("运行设置已保存", "ok");
          loadSettings();
        })
        .catch(function (err) {
          toast("设置保存失败: " + err.message, "err");
        })
        .finally(function () {
          save.disabled = false;
        });
    });
    wrap.appendChild(save);
    return wrap;
  }

  function settingInput(label, type, placeholder) {
    var field = el("label", "field");
    field.appendChild(el("span", "label", label));
    var input = el("input");
    input.type = type || "text";
    if (placeholder) input.placeholder = placeholder;
    field.appendChild(input);
    return { field: field, input: input };
  }

  function settingCheckbox(label, checked) {
    var field = el("label", "row gap");
    var input = el("input");
    input.type = "checkbox";
    input.checked = checked;
    field.appendChild(input);
    field.appendChild(el("span", "", label));
    return { field: field, input: input };
  }

  function settingSelect(label, options, selected) {
    var field = el("label", "field");
    field.appendChild(el("span", "label", label));
    var input = el("select");
    options.forEach(function (value) {
      var option = el("option", "", value[1]);
      option.value = value[0];
      option.selected = value[0] === selected;
      input.appendChild(option);
    });
    field.appendChild(input);
    return { field: field, input: input };
  }

  // ---------- System ----------

  function loadSystem() {
    var host = $("system-body");
    if (!host) return;
    clear(host);
    host.appendChild(el("p", "muted", "加载中…"));
    api("GET", "/admin/system")
      .then(function (sys) {
        state.system = sys;
        setText($("shell-version"), (sys && sys.version) || "管理后台");
        clear(host);
        host.appendChild(renderSystem(sys));
      })
      .catch(function (err) {
        clear(host);
        host.appendChild(el("p", "error", err.message || "加载失败"));
      });
  }

  function renderSystem(sys) {
    var wrap = el("div", "stack");
    var dl = el("dl", "kv");
    addKV(dl, "版本", sys.version);
    addKV(dl, "监听地址", sys.listen);
    addKV(dl, "数据目录", sys.data_dir);
    addKV(dl, "对话后端", sys.chat_backend);
    if (sys.upstream) {
      addKV(dl, "上游地址", sys.upstream.base_url);
      addKV(dl, "客户端版本", sys.upstream.client_version);
      addKV(dl, "客户端标识", sys.upstream.client_identifier);
      addKV(dl, "User-Agent", sys.upstream.user_agent);
      addKV(dl, "Token 鉴权头", String(!!sys.upstream.token_auth));
    }
    if (sys.anthropic) {
      addKV(dl, "Anthropic 入口", sys.anthropic.enabled ? "已启用" : "已关闭");
    }
    if (sys.pool) {
      var pool = sys.pool;
      addKV(dl, "账号池可用", String(pool.available || 0) + " / " + String(pool.total || 0));
      addKV(dl, "冷却中", pool.cooling || 0);
      addKV(dl, "已禁用", pool.disabled || 0);
      addKV(dl, "令牌已过期", pool.expired || 0);
      addKV(dl, "下次恢复", pool.next_recovery_at ? fmtTime(pool.next_recovery_at) : "—");
      addKV(dl, "最近成功", pool.last_success_at ? fmtTime(pool.last_success_at) : "—");
    }
    if (sys.limits) {
      var lim = sys.limits;
      addKV(dl, "最大请求体", String(lim.MaxBodyBytes != null ? lim.MaxBodyBytes : lim.max_body_bytes || "—"));
      addKV(dl, "请求超时(秒)", String(lim.RequestTimeoutSec != null ? lim.RequestTimeoutSec : lim.request_timeout_sec || "—"));
      addKV(dl, "最大并发", String(lim.MaxConcurrent != null ? lim.MaxConcurrent : lim.max_concurrent || "—"));
    }
    wrap.appendChild(dl);

    var raw = el("details");
    raw.appendChild(el("summary", "", "调试：原始 JSON"));
    var pre = el("pre", "code");
    pre.textContent = JSON.stringify(sys, null, 2);
    raw.appendChild(pre);
    wrap.appendChild(raw);
    return wrap;
  }

  function addKV(dl, k, v) {
    dl.appendChild(el("dt", "", k));
    dl.appendChild(el("dd", "", v == null || v === "" ? "—" : String(v)));
  }

  // ---------- Integration ----------

  function renderIntegration() {
    var origin = location.origin || "http://127.0.0.1:8080";
    var anthropic =
      'export ANTHROPIC_BASE_URL="' +
      origin +
      '"\n' +
      'export ANTHROPIC_AUTH_TOKEN="<客户端密钥>"';
    var openai =
      'export OPENAI_BASE_URL="' +
      origin +
      '/v1"\n' +
      'export OPENAI_API_KEY="<客户端密钥>"';
    setText($("snippet-anthropic"), anthropic);
    setText($("snippet-openai"), openai);
  }

  function copyIntegration() {
    var a = ($("snippet-anthropic") && $("snippet-anthropic").textContent) || "";
    var o = ($("snippet-openai") && $("snippet-openai").textContent) || "";
    var all = a + "\n\n" + o;
    copyText(all).then(
      function () {
        toast("已复制接入片段", "ok");
      },
      function () {
        toast("复制失败", "err");
      }
    );
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (ok) resolve();
        else reject(new Error("复制失败"));
      } catch (e) {
        reject(e);
      }
    });
  }

  // ---------- Wire events ----------

  function bind() {
    var loginForm = $("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", function (e) {
        e.preventDefault();
        login(($("login-key") && $("login-key").value) || "");
      });
    }

    var logoutBtn = $("btn-logout");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        logout(false);
      });
    }

    var credRefresh = $("btn-cred-refresh-list");
    if (credRefresh) credRefresh.addEventListener("click", loadCredentials);

    var credentialSearch = $("credential-search");
    if (credentialSearch) {
      credentialSearch.addEventListener("input", function () {
        state.credentialQuery = credentialSearch.value || "";
        state.credentialPage = 1;
        if (state.credentialSearchTimer) clearTimeout(state.credentialSearchTimer);
        state.credentialSearchTimer = setTimeout(loadCredentials, 250);
      });
    }

    var credentialStatus = $("credential-status");
    if (credentialStatus) {
      credentialStatus.addEventListener("change", function () {
        state.credentialStatus = credentialStatus.value || "all";
        state.credentialPage = 1;
        loadCredentials();
      });
    }

    var credentialPageSize = $("credential-page-size");
    if (credentialPageSize) {
      credentialPageSize.addEventListener("change", function () {
        state.credentialPageSize = Number(credentialPageSize.value) || 24;
        state.credentialPage = 1;
        loadCredentials();
      });
    }

    var impDef = $("btn-import-default");
    if (impDef) impDef.addEventListener("click", importDefaultGrok);

    var deviceLogin = $("btn-device-login");
    if (deviceLogin) deviceLogin.addEventListener("click", startDeviceLogin);

    var impRaw = $("btn-import-raw");
    if (impRaw) impRaw.addEventListener("click", openImportRawModal);

    var clientRefresh = $("btn-client-refresh");
    if (clientRefresh) clientRefresh.addEventListener("click", loadClients);

    var clientCreate = $("btn-client-create");
    if (clientCreate) clientCreate.addEventListener("click", openCreateClientModal);

    var sysRefresh = $("btn-system-refresh");
    if (sysRefresh) sysRefresh.addEventListener("click", loadSystem);

    var settingsRefresh = $("btn-settings-refresh");
    if (settingsRefresh) settingsRefresh.addEventListener("click", loadSettings);

    var copyInt = $("btn-copy-integration");
    if (copyInt) copyInt.addEventListener("click", copyIntegration);

    var modalClose = $("modal-close");
    if (modalClose) modalClose.addEventListener("click", closeModal);

    var modal = $("modal");
    if (modal) {
      modal.addEventListener("click", function (e) {
        if (e.target && e.target.getAttribute("data-close") === "1") closeModal();
      });
    }

    window.addEventListener("hashchange", render);
  }

  function boot() {
    bind();
    // Keep the admin key only in this page's JavaScript memory. Reloading the
    // page intentionally requires re-authentication.
    state.key = "";
    if (state.key) {
      api("GET", "/admin/system")
        .then(function (sys) {
          state.system = sys;
          setText($("shell-version"), (sys && sys.version) || "管理后台");
          if (!location.hash || location.hash === "#" || location.hash === "#/") {
            navigate("credentials");
          }
          render();
        })
        .catch(function () {
          if (!state.key) {
            navigate("login");
          }
          render();
        });
    } else {
      if (!location.hash || location.hash === "#" || location.hash === "#/credentials") {
        navigate("login");
      }
      render();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
