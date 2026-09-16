(() => {
  "use strict";

  const feed = document.querySelector("#audit-events");
  const refreshButton = document.querySelector("#audit-refresh");
  const pauseButton = document.querySelector("#audit-pause");
  const status = document.querySelector("#audit-status");
  const total = document.querySelector("#audit-total");
  if (!feed || !refreshButton || !status) return;

  const pollUrl = feed.dataset.pollUrl;
  let latestId = Number.parseInt(feed.dataset.latestId || "0", 10);
  let paused = false;
  let inFlight = false;

  function textElement(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = value;
    return element;
  }

  function detailPair(list, label, value, options = {}) {
    list.append(textElement("dt", "", label));
    const description = textElement("dd", "", value);
    if (options.machine) {
      description.dir = "ltr";
      description.translate = false;
    }
    list.append(description);
  }

  function eventRow(event) {
    const row = document.createElement("tr");
    row.dataset.eventId = String(event.id);

    const timeCell = document.createElement("td");
    const time = textElement("time", "audit-time", event.display_time);
    time.dateTime = event.created_at;
    timeCell.append(time);

    const outcomeCell = document.createElement("td");
    outcomeCell.append(textElement("span", `audit-badge ${event.outcome}`, event.outcome_label));

    const actionCell = document.createElement("td");
    actionCell.append(document.createTextNode(event.event_label));
    actionCell.append(textElement("span", "audit-secondary", `${event.channel} · ${event.target}`));

    const actorCell = textElement("td", "", event.actor);
    const ipCell = textElement("td", "audit-ip", event.source_ip);
    ipCell.dir = "ltr";
    ipCell.translate = false;

    const detailCell = document.createElement("td");
    const details = document.createElement("details");
    details.className = "audit-detail";
    details.append(textElement("summary", "", "보기"));
    const list = document.createElement("dl");
    detailPair(list, "대상", event.target);
    detailPair(list, "경로", event.channel);
    detailPair(list, "사유", event.reason);
    detailPair(list, "IP", event.source_ip, { machine: true });
    detailPair(list, "User-Agent", event.user_agent);
    detailPair(list, "요청 ID", event.request_id, { machine: true });
    details.append(list);
    detailCell.append(details);

    row.append(timeCell, outcomeCell, actionCell, actorCell, ipCell, detailCell);
    return row;
  }

  function updateSummary(summary) {
    const values = {
      "metric-login-success": summary.login_success,
      "metric-login-failure": summary.login_failure,
      "metric-active-users": summary.active_users,
      "metric-denied": summary.denied,
    };
    for (const [id, value] of Object.entries(values)) {
      const metric = document.getElementById(id);
      if (metric) metric.textContent = String(value);
    }
  }

  function setStatus(state, label) {
    if (status.dataset.state === state && status.textContent === label) return;
    status.dataset.state = state;
    status.textContent = label;
  }

  function trimRows() {
    const rows = feed.querySelectorAll("tr[data-event-id]");
    for (let index = 200; index < rows.length; index += 1) rows[index].remove();
  }

  async function poll() {
    if (!pollUrl || paused || inFlight || document.hidden) return;
    inFlight = true;
    let pollAgain = false;
    try {
      const url = new URL(pollUrl, window.location.origin);
      url.searchParams.set("after_id", String(latestId));
      const response = await fetch(url, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const empty = document.querySelector("#audit-empty");
      if (data.events.length && empty) empty.remove();
      for (const event of data.events) {
        feed.insertBefore(eventRow(event), feed.firstChild);
        latestId = Math.max(latestId, event.id);
      }
      if (total && data.events.length) {
        const nextTotal = Number.parseInt(total.dataset.total || "0", 10) + data.events.length;
        total.dataset.total = String(nextTotal);
        total.textContent = `총 ${nextTotal.toLocaleString("ko-KR")}건`;
      }
      trimRows();
      updateSummary(data.summary);
      setStatus("live", "자동 갱신 중");
      pollAgain = data.has_more;
    } catch (_error) {
      setStatus("error", "연결 확인 필요");
    } finally {
      inFlight = false;
      if (pollAgain) window.setTimeout(poll, 0);
    }
  }

  refreshButton.addEventListener("click", () => {
    if (pollUrl) poll();
    else window.location.reload();
  });

  if (pauseButton) {
    pauseButton.addEventListener("click", () => {
      paused = !paused;
      pauseButton.setAttribute("aria-pressed", String(paused));
      pauseButton.textContent = paused ? "재개" : "일시정지";
      setStatus(paused ? "paused" : "live", paused ? "자동 갱신 멈춤" : "자동 갱신 중");
      if (!paused) poll();
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) poll();
  });
  if (pollUrl) window.setInterval(poll, 3000);
})();
