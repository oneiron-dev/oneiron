// The authorize page's one script (FIX 4902): it polls the request's status with the page's
// token in the `x-oneiron-oauth-page` header, never in a URL, and sends the browser back to the
// app once the owner has answered in his inbox.
(() => {
  "use strict";
  const token = document.querySelector('meta[name="oauth-page-token"]').content;
  const status = document.getElementById("status");
  const say = (text) => {
    status.textContent = text;
  };
  const poll = async () => {
    let reply;
    try {
      reply = await fetch("/oauth/authorize/status", {
        headers: { "x-oneiron-oauth-page": token },
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch (_) {
      setTimeout(poll, 5000);
      return;
    }
    let body = {};
    try {
      body = await reply.json();
    } catch (_) {
      body = {};
    }
    switch (body.status) {
      case "pending":
        setTimeout(poll, 2000);
        return;
      case "allowed":
        say("Allowed. Returning you to the app.");
        window.location.replace(body.redirect);
        return;
      case "denied":
        say("Denied. Returning you to the app.");
        window.location.replace(body.redirect);
        return;
      case "expired":
        say("This sign-in request expired. Start the sign-in again from the app.");
        return;
      default:
        if (reply.status >= 500) {
          setTimeout(poll, 5000);
          return;
        }
        say("This sign-in request is no longer open. Start the sign-in again from the app.");
    }
  };
  poll();
})();
