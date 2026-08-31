"""The operator console: everything that is not a payment API call.

A server-rendered HTML console, mounted under ``/ui``, that does the four jobs
an EBICS deployment needs a human for: registering bank connections, walking a
subscriber through `INI` → `HIA` → `HPB`, reading what happened to an order,
and looking at the statements that came back.

**It renders HTML on the server and ships no build step.** Jinja templates and
a Material Design 3 stylesheet, which is inlined into the page rather than
served as a static file -- so there is no mount to exempt from the
deny-by-default middleware, no asset URL to get wrong behind a reverse proxy,
and no second request before a page is legible. There is **one** script, inlined
in ``<head>``: the three-state theme toggle, which is the only thing here that
stops working when scripting is off. A page that has to refresh while a key job
runs still says so with ``<meta http-equiv="refresh">`` rather than by polling.

**It performs no key operation.** The console runs in the API process, which is
refused the custody secret at startup, so a button that generates a key, sends
an `INI` or reads an `HPB` response would need a decryption in the process that
handled the click. Every one of them is instead a row in
:mod:`painfree.keyjobs` that the worker claims. What the console does itself is
exactly what needs no key: reading public fingerprints, printing the letter,
listing orders, re-queueing one.

**Every route carries a scope**, the same way ``/v1`` does. The middleware in
:mod:`painfree.authn` refuses an unauthenticated request before the route is
reached, and ``Depends(requires(...))`` refuses an authenticated one that lacks
the privilege. Controls the caller may not use are hidden *as well*, which is a
courtesy and not the control: hiding a button is not authorisation, and
``tests/test_service_ui.py`` posts to the routes directly to prove it.

**What a browser gets instead of a JSON error.** A `401` on a page navigation is
a redirect to the login flow rather than an envelope no browser will render,
and a `403` or a `404` is an HTML page carrying the same code, message and
request id the JSON body would have. The API's error shape is untouched: the
distinction is made on the ``Accept`` header and the path.
"""

from painfree.ui import access_views, account_views, reference_views
from painfree.ui.rendering import render, wants_html
from painfree.ui.views import router

#: Every router the console is made of, in the order they are included. Four
#: modules rather than one because `views` reached the 1 000-line cap: the
#: split is by what a page is *about* -- the work (`views`), the deployment
#: itself (`reference_views`), who may reach it (`access_views`), and who may
#: sign in at all when there is no identity provider to ask (`account_views`).
ROUTERS = (router, reference_views.router, access_views.router,
           account_views.router)

__all__ = ["ROUTERS", "render", "router", "wants_html"]
