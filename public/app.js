// Consulta a sessão na mesma origem e atualiza a área de autenticação.
(function () {
  var status = document.getElementById("status");
  var loginLinks = document.getElementById("login-links");
  var logoutForm = document.getElementById("logout-form");

  fetch("/api/me", { credentials: "same-origin" })
    .then(function (response) { return response.ok ? response.json() : null; })
    .then(function (user) {
      if (user) {
        status.textContent = "Sessão de " + (user.email || user.displayName) + ".";
        loginLinks.style.display = "none";
        logoutForm.style.display = "block";
      } else {
        status.textContent = "Nenhuma sessão neste navegador.";
        loginLinks.style.display = "flex";
        logoutForm.style.display = "none";
      }
    })
    .catch(function () {
      status.textContent = "Não foi possível consultar a sessão.";
    });
})();
