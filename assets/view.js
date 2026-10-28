/*
 * deploy-dynamic : vue joueur d'un défi à instance.
 *
 * Le rendu n'utilise que des classes .ddeploy-* et des boutons Bootstrap :
 * l'apparence vient de view.css (styles par défaut) et du thème actif.
 * CTFd recharge ce script à chaque ouverture d'un défi de ce type ; l'état
 * partagé (minuteur, écouteur global) vit donc sur window.ddeploy.
 */
CTFd._internal.challenge.data = undefined;

CTFd._internal.challenge.renderer = CTFd._internal.markdown;

CTFd._internal.challenge.preRender = function () {};

CTFd._internal.challenge.render = function (markdown) {
  return CTFd._internal.challenge.renderer.parse(markdown);
};

CTFd._internal.challenge.postRender = function () {
  window.ddeploy.mount();
};

(function () {
  "use strict";

  var WEB_PORTS = [80, 3000, 4000, 5000, 8000, 8080, 8888];
  var TLS_PORTS = [443, 8443];

  var state = window.ddeploy || (window.ddeploy = {});

  /* ---------------------------------------------------------------
     Utilitaires
     --------------------------------------------------------------- */
  function esc(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Les messages d'erreur du serveur contiennent parfois du HTML (<br>, <b>) :
  // on n'en garde que le texte, analysé dans un document inerte.
  function plainText(message) {
    var html = String(message || "").replace(/<br\s*\/?>/gi, "\n");
    var doc = new DOMParser().parseFromString(html, "text/html");
    return (doc.body.textContent || "").trim();
  }

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function data() {
    return CTFd._internal.challenge.data || {};
  }

  // La vue d'un défi précédent peut encore être dans le DOM : on ne prend
  // que le conteneur qui correspond au défi chargé.
  function root() {
    var el = document.getElementById("docker_container");
    if (!el || String(el.getAttribute("data-challenge-id")) !== String(data().id)) return null;
    return el;
  }

  function setView(name, html) {
    var el = root();
    if (!el) return null;
    state.view = name;
    el.innerHTML = html;
    return el;
  }

  function button(action, label, icon, classes, extra) {
    return (
      '<button type="button" class="btn ' + classes + ' ddeploy-btn" data-ddeploy-action="' + action + '"' + (extra || "") + ">" +
      (icon ? '<i class="fas ' + icon + '" aria-hidden="true"></i> ' : "") +
      label +
      "</button>"
    );
  }

  /* ---------------------------------------------------------------
     Rendus
     --------------------------------------------------------------- */
  function renderLoading(text) {
    stopTimer();
    setView(
      "loading",
      '<div class="ddeploy-loading">' +
        '<i class="fas fa-circle-notch fa-spin" aria-hidden="true"></i>' +
        "<span>" + esc(text) + "</span>" +
        "</div>",
    );
  }

  function renderIdle() {
    stopTimer();
    setView(
      "idle",
      '<div class="ddeploy-idle">' +
        '<p class="ddeploy-idle-text">Ce défi se joue sur une instance qui vous est dédiée.</p>' +
        button("start", "Lancer l'instance", "fa-play", "btn-primary ddeploy-btn-start") +
        "</div>",
    );
  }

  function renderLogin() {
    var next = encodeURIComponent(window.location.pathname + window.location.hash);
    setView(
      "login",
      '<div class="ddeploy-idle">' +
        '<p class="ddeploy-idle-text">Connectez-vous pour lancer une instance de ce défi.</p>' +
        '<a class="btn btn-primary ddeploy-btn ddeploy-btn-start" href="' + esc(CTFd.config.urlRoot + "/login?next=" + next) + '">' +
        '<i class="fas fa-sign-in-alt" aria-hidden="true"></i> Se connecter</a>' +
        "</div>",
    );
  }

  function renderError(message) {
    stopTimer();
    setView(
      "error",
      '<div class="alert alert-danger ddeploy-error" role="alert">' +
        '<p class="ddeploy-error-text">' + esc(plainText(message) || "Une erreur inattendue est survenue.") + "</p>" +
        button("refresh", "Réessayer", "fa-sync-alt", "btn-sm btn-outline-secondary ddeploy-btn-retry") +
        "</div>",
    );
  }

  function normalizePorts(ports) {
    var list = Array.isArray(ports) ? ports : String(ports || "").split(",");
    return list
      .map(function (p) {
        if (typeof p === "object" && p !== null) return p;
        var s = String(p).trim();
        if (!s) return null;
        if (s.indexOf(":") >= 0) {
          var idx = s.lastIndexOf(":");
          return { container: s.substring(0, idx), host: s.substring(idx + 1) };
        }
        return { container: null, host: s };
      })
      .filter(Boolean);
  }

  function describePort(port, host) {
    var hostPort = String(port.host).split("/")[0].trim();
    var containerPort = port.container ? parseInt(String(port.container).split("/")[0], 10) : null;
    var proto = port.container ? String(port.container).split("/")[1] : "tcp";

    if (containerPort === 22) {
      return { kind: "ssh", icon: "fa-terminal", value: "ssh user@" + host + " -p " + hostPort };
    }
    if (TLS_PORTS.indexOf(containerPort) >= 0) {
      return { kind: "https", icon: "fa-lock", value: "https://" + host + ":" + hostPort, link: true };
    }
    if (WEB_PORTS.indexOf(containerPort) >= 0) {
      return { kind: "http", icon: "fa-globe", value: "http://" + host + ":" + hostPort, link: true };
    }
    if (proto === "udp") {
      return { kind: "udp", icon: "fa-network-wired", value: host + ":" + hostPort + "/udp" };
    }
    return { kind: "tcp", icon: "fa-plug", value: "nc " + host + " " + hostPort };
  }

  function renderLink(entry) {
    var value = esc(entry.value);
    var text = entry.link
      ? '<a class="ddeploy-link-text" href="' + value + '" target="_blank" rel="noopener noreferrer">' + value + "</a>"
      : '<span class="ddeploy-link-text">' + value + "</span>";
    return (
      '<li class="ddeploy-link" data-kind="' + entry.kind + '">' +
      '<i class="fas ' + entry.icon + ' ddeploy-link-icon" aria-hidden="true"></i>' +
      '<span class="ddeploy-link-kind">' + entry.kind + "</span>" +
      text +
      '<button type="button" class="ddeploy-copy" data-ddeploy-action="copy" data-value="' + value + '" aria-label="Copier ' + value + '">Copier</button>' +
      "</li>"
    );
  }

  function actionsHtml() {
    var locked = ' disabled data-ddeploy-locked';
    var countdown = ' <span class="ddeploy-countdown" data-ddeploy-countdown></span>';
    return (
      button("restart", "Redémarrer" + countdown, "fa-redo", "btn-sm btn-outline-secondary ddeploy-btn-restart", locked) +
      button("stop", "Arrêter" + countdown, "fa-stop", "btn-sm btn-outline-danger ddeploy-btn-stop", locked)
    );
  }

  // Remplace « host » / « port » dans les infos de connexion du défi par ceux de l'instance
  function fillConnectionInfo(item, ports) {
    var info = document.querySelector(".challenge-connection-info");
    if (!info || !ports.length) return;
    var firstPort = String(ports[0].host).split("/")[0].trim();
    var html = info.innerHTML
      .replace(/\bhost\b/gi, esc(item.host))
      .replace(/\bport\b|\b\d{5}\b/gi, esc(firstPort));
    if (html.indexOf("<a") < 0) {
      html = html.replace(/(https?:\/\/[^\s<"']+)/, function (url) {
        return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + "</a>";
      });
    }
    info.innerHTML = html;
  }

  function renderRunning(item) {
    state.item = item;
    var ports = normalizePorts(item.ports);
    var links = ports
      .map(function (port) {
        return renderLink(describePort(port, item.host));
      })
      .join("");
    var since = item.timestamp
      ? new Date(item.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : "";

    var el = setView(
      "running",
      '<div class="ddeploy-card" data-state="running">' +
        '<div class="ddeploy-card-header">' +
        '<span class="ddeploy-status-dot" aria-hidden="true"></span>' +
        '<span class="ddeploy-title">Instance en ligne</span>' +
        (since ? '<span class="ddeploy-meta">depuis ' + esc(since) + "</span>" : "") +
        "</div>" +
        '<div class="ddeploy-card-body">' +
        (links ? '<ul class="ddeploy-links">' + links + "</ul>" : "") +
        '<div class="ddeploy-actions" data-ddeploy-actions>' + actionsHtml() + "</div>" +
        "</div>" +
        "</div>",
    );
    if (!el) return;
    fillConnectionInfo(item, ports);
    startTimer(parseInt(item.revert_time, 10) * 1000);
  }

  function renderConfirmStop() {
    var actions = root() && root().querySelector("[data-ddeploy-actions]");
    if (!actions) return;
    state.view = "confirm";
    actions.outerHTML =
      '<div class="ddeploy-confirm" role="group" aria-label="Confirmer l\'arrêt de l\'instance">' +
      '<p class="ddeploy-confirm-text">Arrêter l\'instance ? Son état sera perdu.</p>' +
      button("stop-confirm", "Oui, arrêter", "fa-stop", "btn-sm btn-danger") +
      button("stop-cancel", "Annuler", "", "btn-sm btn-link") +
      "</div>";
    var cancel = root().querySelector('[data-ddeploy-action="stop-cancel"]');
    if (cancel) cancel.focus();
  }

  /* ---------------------------------------------------------------
     Minuteur : redémarrage et arrêt bloqués 30 s après le lancement
     --------------------------------------------------------------- */
  function stopTimer() {
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
  }

  function startTimer(unlockAt) {
    stopTimer();
    function tick() {
      var el = root();
      if (!el) {
        stopTimer();
        return;
      }
      var left = Math.ceil((unlockAt - Date.now()) / 1000);
      var countdowns = el.querySelectorAll("[data-ddeploy-countdown]");
      if (!(left > 0)) {
        el.querySelectorAll("[data-ddeploy-locked]").forEach(function (b) {
          b.disabled = false;
        });
        countdowns.forEach(function (c) {
          c.textContent = "";
        });
        stopTimer();
        return;
      }
      var text = Math.floor(left / 60) + ":" + pad(left % 60);
      countdowns.forEach(function (c) {
        c.textContent = text;
      });
    }
    tick();
    if (unlockAt > Date.now()) {
      state.timer = setInterval(tick, 1000);
    }
  }

  /* ---------------------------------------------------------------
     Actions
     --------------------------------------------------------------- */
  function refresh() {
    var image = data().docker_image;
    return CTFd.fetch("/api/v1/docker_instances")
      .then(function (response) {
        return response.json();
      })
      .then(function (result) {
        var item = (result.data || []).filter(function (i) {
          return i.docker_image === image;
        })[0];
        if (item) {
          renderRunning(item);
        } else {
          renderIdle();
        }
      })
      .catch(function () {
        renderError("Impossible de récupérer l'état de l'instance.");
      });
  }

  function deploy(stop) {
    renderLoading(stop ? "Arrêt de l'instance…" : "Démarrage de l'instance…");
    var url =
      "/api/v1/container?name=" + encodeURIComponent(data().docker_image) +
      "&challenge=" + encodeURIComponent(data().name) +
      (stop ? "&stopcontainer=True" : "");

    CTFd.fetch(url, { method: "GET" })
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (body) {
            if (!response.ok) {
              throw new Error(
                (body && body.message) ||
                  (stop ? "L'instance n'a pas pu être arrêtée." : "L'instance n'a pas pu être lancée."),
              );
            }
          });
      })
      .then(refresh)
      .catch(function (error) {
        renderError(error.message);
      });
  }

  function copyFallback(value, host) {
    // Hors HTTPS, l'API presse-papiers n'existe pas. La zone de texte est placée
    // dans la fenêtre du défi pour ne pas être bloquée par le piège à focus de Bootstrap.
    var area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    host.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    area.remove();
    return ok;
  }

  function copy(btn) {
    var value = btn.getAttribute("data-value");
    function done() {
      btn.textContent = "Copié !";
      btn.classList.add("is-copied");
      setTimeout(function () {
        btn.textContent = "Copier";
        btn.classList.remove("is-copied");
      }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(done, function () {
        if (copyFallback(value, btn.parentNode)) done();
      });
    } else if (copyFallback(value, btn.parentNode)) {
      done();
    }
  }

  function onClick(event) {
    var btn = event.target.closest("[data-ddeploy-action]");
    if (!btn || btn.disabled) return;
    switch (btn.getAttribute("data-ddeploy-action")) {
      case "start":
      case "restart":
        deploy(false);
        break;
      case "stop":
        renderConfirmStop();
        break;
      case "stop-confirm":
        deploy(true);
        break;
      case "stop-cancel":
        renderRunning(state.item);
        var stopBtn = root() && root().querySelector('[data-ddeploy-action="stop"]');
        if (stopBtn) stopBtn.focus();
        break;
      case "copy":
        copy(btn);
        break;
      case "refresh":
        renderLoading("Chargement de l'instance…");
        refresh();
        break;
    }
  }

  /* ---------------------------------------------------------------
     Montage
     --------------------------------------------------------------- */
  state.mount = function (attempt) {
    var el = root();
    if (!el) {
      // postRender est appelé avant qu'Alpine n'insère la vue : on attend le conteneur
      attempt = attempt || 0;
      if (attempt < 120) {
        requestAnimationFrame(function () {
          state.mount(attempt + 1);
        });
      }
      return;
    }
    if (el.getAttribute("data-ddeploy-mounted")) return;
    el.setAttribute("data-ddeploy-mounted", "1");
    el.addEventListener("click", onClick);

    if (!(window.init && window.init.userId)) {
      renderLogin();
      return;
    }
    refresh();
  };

  // Après une soumission, le thème core émet « load-challenges » : si le flag est bon,
  // le serveur a supprimé l'instance, on met donc l'affichage à jour.
  if (!state.listening) {
    state.listening = true;
    window.addEventListener("load-challenges", function () {
      if (state.view === "running" && root()) {
        refresh();
      }
    });
  }
})();
