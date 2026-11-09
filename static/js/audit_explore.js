(() => {
    const panel = document.querySelector("[data-activity-url]");
    if (!panel) return;

    const toggle = panel.querySelector("[data-activity-toggle]");
    const status = panel.querySelector("[data-activity-status]");
    const list = panel.querySelector("[data-activity-items]");
    const levels = new Set(["NORMAL", "ADVERTENCIA", "CRITICO", "ANOMALIA"]);
    let paused = false;
    let timer;
    let pending;
    let previousIds = null;
    let queuedEvents;

    function activityItem(event) {
        const item = document.createElement("li");
        const url = new URL(event.url, window.location.origin);
        if (url.origin !== window.location.origin) return null;
        const link = document.createElement("a");
        const action = String(event.tipo_accion || "Evento").replaceAll("_", " ");
        link.href = url.href;
        link.textContent = `#${event.event_id} · ${action}`;
        const risk = levels.has(event.nivel_alerta) ? event.nivel_alerta : "NORMAL";
        const badge = document.createElement("span");
        badge.className = `badge badge-${risk.toLowerCase()}`;
        badge.textContent = risk;
        const time = document.createElement("time");
        time.dateTime = event.timestamp || "";
        time.textContent = event.timestamp ? `${event.timestamp.slice(0, 19).replace("T", " ")} UTC` : "Sin fecha";
        item.append(link, badge, time);
        return item;
    }

    function render(events) {
        const ids = events.map(event => event.event_id);
        if (previousIds && ids.join(",") === previousIds.join(",")) return;
        // Wait until focus leaves the list so that a poll cannot move a keyboard user.
        if (list.contains(document.activeElement)) {
            queuedEvents = events;
            return;
        }
        const previous = new Set(previousIds || []);
        const newCount = ids.filter(id => !previous.has(id)).length;
        list.replaceChildren(...events.map(activityItem).filter(Boolean));
        if (!ids.length) {
            status.textContent = "Todavía no hay actividad.";
        } else if (!previousIds) {
            status.textContent = "Actividad conectada.";
        } else if (newCount) {
            status.textContent = newCount === 1 ? "Se recibió 1 evento nuevo." : `Se recibieron ${newCount} eventos nuevos.`;
        }
        previousIds = ids;
    }

    function canPoll() {
        return !paused && !document.hidden;
    }

    function schedule() {
        window.clearTimeout(timer);
        if (canPoll()) timer = window.setTimeout(poll, 15000);
    }

    async function poll() {
        if (!canPoll() || pending) return;
        const controller = new AbortController();
        pending = controller;
        const deadline = window.setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(panel.dataset.activityUrl, {
                headers: { Accept: "application/json" },
                cache: "no-store",
                signal: controller.signal,
            });
            if (!response.ok || response.redirected) throw new Error("Actividad no disponible");
            const { events } = await response.json();
            if (!Array.isArray(events)) throw new Error("Respuesta inválida");
            if (pending === controller && canPoll()) {
                if (status.dataset.unavailable) {
                    status.textContent = "Actividad reconectada.";
                    delete status.dataset.unavailable;
                }
                render(events);
            }
        } catch {
            if (pending === controller && canPoll()) {
                status.dataset.unavailable = "true";
                status.textContent = "No pudimos consultar la actividad. Se reintentará automáticamente.";
            }
        } finally {
            window.clearTimeout(deadline);
            if (pending === controller) {
                pending = undefined;
                schedule();
            }
        }
    }

    function stop() {
        window.clearTimeout(timer);
        pending?.abort();
        pending = undefined;
        queuedEvents = undefined;
    }

    list.addEventListener("focusout", event => {
        if (!list.contains(event.relatedTarget) && queuedEvents && !paused) {
            const events = queuedEvents;
            queuedEvents = undefined;
            window.setTimeout(() => { if (canPoll()) render(events); }, 0);
        }
    });
    toggle.hidden = false;
    toggle.addEventListener("click", () => {
        paused = !paused;
        toggle.textContent = paused ? "Reanudar actividad" : "Pausar actividad";
        status.textContent = paused ? "Actividad pausada." : "Actividad activa.";
        if (paused) stop();
        else poll();
    });
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) stop();
        else if (!paused) poll();
    });
    poll();
})();
