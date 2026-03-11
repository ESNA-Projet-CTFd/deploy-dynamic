CTFd._internal.challenge.data = undefined;

CTFd._internal.challenge.renderer = CTFd._internal.markdown;

CTFd._internal.challenge.preRender = function () {};

CTFd._internal.challenge.render = function (markdown) {
  return CTFd._internal.challenge.renderer.parse(markdown);
};

CTFd._internal.challenge.postRender = function () {
  const containername = CTFd._internal.challenge.data.docker_image;
  get_docker_status(containername);
  createWarningModalBody();
};

function createWarningModalBody() {
  if (CTFd.lib.$("#warningModalBody").length === 0) {
    CTFd.lib.$("body").append('<div id="warningModalBody"></div>');
  }
}

function get_docker_status(container) {
  CTFd.lib
    .$("#docker_container")
    .html(
      '<div class="text-center py-3 text-muted"><i class="fas fa-circle-notch fa-spin"></i></div>',
    );

  CTFd.fetch("/api/v1/docker_instances")
    .then((response) => response.json())
    .then((result) => {
      let found = false;

      result.data.forEach((item) => {
        if (item.docker_image !== container) return;
        found = true;

        var ports = Array.isArray(item.ports)
          ? item.ports
          : String(item.ports).split(",");
        var portNum = String(ports[0]).split("/")[0].trim();

        // Replace placeholders in the challenge description
        var $connInfo = CTFd.lib.$(".challenge-connection-info");
        if ($connInfo.length > 0) {
          var connHtml = $connInfo.html();
          connHtml = connHtml.replace(/\bhost\b/gi, item.host);
          connHtml = connHtml.replace(/\bport\b|\b\d{5}\b/gi, portNum);
          if (!connHtml.includes("<a")) {
            connHtml = connHtml.replace(
              /(https?:\/\/[^\s<"']+)/,
              (url) =>
                `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`,
            );
          }
          $connInfo.html(connHtml);
        }

        // Build clickable links for each port
        var linksHtml = ports
          .map((port) => {
            var p = String(port).split("/")[0].trim().split(" ")[0];
            var url = `http://${item.host}:${p}`;
            return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="docker-link">
                    <i class="fas fa-external-link-alt"></i> ${url}
                </a>`;
          })
          .join("");

        var instanceId = String(item.instance_id).substring(0, 10);
        var escapedImage = item.docker_image.replace(/'/g, "\\'");

        CTFd.lib.$("#docker_container").html(`
                <div class="docker-card">
                    <div class="docker-card-header">
                        <span class="docker-status-dot"></span>
                        Instance Running
                    </div>
                    <div class="docker-card-body">
                        <div class="docker-links">${linksHtml}</div>
                        <div class="docker-actions">
                            <button id="${instanceId}_restart_btn"
                                    class="btn btn-sm btn-warning"
                                    disabled>
                                <i class="fas fa-redo"></i> Restart Instance
                                <span id="${instanceId}_countdown" class="docker-countdown-inline"></span>
                            </button>
                            <button id="${instanceId}_destroy_btn"
                                    class="btn btn-sm btn-danger"
                                    disabled>
                                <i class="fas fa-trash-alt"></i> Destroy Instance
                            </button>
                        </div>
                    </div>
                </div>
            `);

        // Countdown — enables Restart button when done
        var countDownDate = new Date(
          parseInt(item.revert_time) * 1000,
        ).getTime();
        var x = setInterval(function () {
          var now = new Date().getTime();
          var distance = countDownDate - now;
          var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
          var seconds = Math.floor((distance % (1000 * 60)) / 1000);
          if (seconds < 10) seconds = "0" + seconds;

          if (distance < 0) {
            clearInterval(x);
            var $btn = CTFd.lib.$("#" + instanceId + "_restart_btn");
            $btn
              .prop("disabled", false)
              .attr("onclick", "start_container('" + escapedImage + "');");
            CTFd.lib.$("#" + instanceId + "_countdown").html("");
            CTFd.lib.$("#" + instanceId + "_destroy_btn")
              .prop("disabled", false)
              .attr("onclick", "destroy_container('" + escapedImage + "');");
          } else {
            CTFd.lib
              .$("#" + instanceId + "_countdown")
              .html(minutes + ":" + seconds);
          }
        }, 1000);
      });

      if (!found) {
        CTFd.lib.$("#docker_container").html(`
                <div class="docker-start-wrap">
                    <a onclick="start_container('${CTFd._internal.challenge.data.docker_image.replace(/'/g, "\\'")}');"
                       class="btn btn-dark docker-start-btn">
                        <i class="fas fa-play"></i> Start Instance
                    </a>
                </div>
            `);
      }
    })
    .catch((error) => {
      console.error("Error fetching docker status:", error);
      CTFd.lib.$("#docker_container").html(`
            <div class="docker-start-wrap">
                <a onclick="start_container('${CTFd._internal.challenge.data.docker_image.replace(/'/g, "\\'")}');"
                   class="btn btn-dark docker-start-btn">
                    <i class="fas fa-play"></i> Start Instance
                </a>
            </div>
        `);
    });
}

function start_container(container) {
  CTFd.lib
    .$("#docker_container")
    .html(
      '<div class="text-center py-3 text-muted">' +
        '<i class="fas fa-circle-notch fa-spin fa-lg"></i> Starting instance\u2026</div>',
    );
  CTFd.fetch(
    "/api/v1/container?name=" +
      encodeURIComponent(container) +
      "&challenge=" +
      encodeURIComponent(CTFd._internal.challenge.data.name),
    {
      method: "GET",
    },
  )
    .then(function (response) {
      return response.json().then(function (json) {
        if (response.ok) {
          get_docker_status(container);
        } else {
          throw new Error(json.message || "Failed to start container");
        }
      });
    })
    .catch(function (error) {
      updateWarningModal({
        title: "Error",
        warningText:
          error.message ||
          "An unknown error occurred when starting your Docker container.",
        buttonText: "Close",
        onClose: function () {
          get_docker_status(container);
        },
      });
    });
}

function destroy_container(container) {
  if (
    !confirm(
      "Destroy the container for:\n" + CTFd._internal.challenge.data.name + "?",
    )
  )
    return;

  CTFd.lib
    .$("#docker_container")
    .html(
      '<div class="text-center py-3 text-muted">' +
        '<i class="fas fa-circle-notch fa-spin fa-lg"></i> Destroying instance\u2026</div>',
    );
  CTFd.fetch(
    "/api/v1/container?name=" +
      encodeURIComponent(container) +
      "&challenge=" +
      encodeURIComponent(CTFd._internal.challenge.data.name) +
      "&stopcontainer=True",
    {
      method: "GET",
    },
  )
    .then(function (response) {
      return response.json().then(function (json) {
        if (response.ok) {
          get_docker_status(container);
        } else {
          throw new Error(json.message || "Failed to destroy container");
        }
      });
    })
    .catch(function (error) {
      updateWarningModal({
        title: "Error",
        warningText:
          error.message ||
          "An unknown error occurred while destroying the container.",
        buttonText: "Close",
        onClose: function () {
          get_docker_status(container);
        },
      });
    });
}

function updateWarningModal({ title, warningText, buttonText, onClose } = {}) {
  const modalHTML = `
        <div id="warningModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; z-index:9999; background-color:rgba(0,0,0,0.5);">
          <div style="position:relative; margin:10% auto; width:420px; background:white; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.3); overflow:hidden;">
            <div class="modal-header bg-dark text-white" style="padding:1rem; display:flex; justify-content:space-between; align-items:center;">
              <h5 class="modal-title" style="margin:0; font-size:1rem;">${title}</h5>
              <button type="button" id="warningCloseBtn" style="border:none; background:none; font-size:1.5rem; line-height:1; cursor:pointer; color:white;">&times;</button>
            </div>
            <div class="modal-body" style="padding:1rem;">${warningText}</div>
            <div class="modal-footer" style="padding:0.75rem 1rem; text-align:right; border-top:1px solid #dee2e6;">
              <button type="button" class="btn btn-dark btn-sm" id="warningOkBtn">${buttonText}</button>
            </div>
          </div>
        </div>
    `;
  CTFd.lib.$("#warningModalBody").html(modalHTML);
  CTFd.lib.$("#warningModal").show();

  const closeModal = () => {
    CTFd.lib.$("#warningModal").hide();
    if (typeof onClose === "function") onClose();
  };
  CTFd.lib.$("#warningCloseBtn").on("click", closeModal);
  CTFd.lib.$("#warningOkBtn").on("click", closeModal);
}

function checkForCorrectFlag() {
  const challengeWindow = document.querySelector("#challenge-window");
  if (
    !challengeWindow ||
    getComputedStyle(challengeWindow).display === "none"
  ) {
    clearInterval(checkInterval);
    checkInterval = null;
    return;
  }
  const strong = document.querySelector(".notification-row .alert strong");
  if (strong && strong.textContent.trim().includes("Correct")) {
    get_docker_status(CTFd._internal.challenge.data.docker_image);
    clearInterval(checkInterval);
    checkInterval = null;
  }
}

if (!checkInterval) {
  var checkInterval = setInterval(checkForCorrectFlag, 1500);
}
