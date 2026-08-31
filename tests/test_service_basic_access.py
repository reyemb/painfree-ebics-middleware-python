"""Authentication changed and authorisation did not, asserted on the same routes.

That is the whole claim of the ``basic`` mode, and the only way to make it
about *every* route rather than about the ones somebody remembered is to use
the tables that already enumerate them. So
:data:`test_service_access.PER_CONNECTION` and
:func:`test_service_oversight.write_routes` are imported and driven with a
password. Both are checked against the application's own router by the tests
that own them, which is what keeps this file honest as routes are added -- the
seven routes this mode added are attacked below without appearing anywhere in
it.

The world is the access tests' world, seeded the same way, with the same
grants. The one difference is the credential.

The second half is the pair of properties a long-lived credential makes urgent:
a grant revoked, an account suspended and a password replaced each take effect
on the **next request**, because the grants and the account row are read from
the database on every one and only the hash verification is remembered.
"""

from __future__ import annotations

import pytest

import basic_world
import test_service_access as access
import test_service_oversight as oversight
from basic_world import (BROWSER, MALLORY, MINE, NOBODY, NOBODY_PASSWORD,
                         ROOT, WATCHER, YOURS, basic, mallory, root, watcher)
from conftest import grant
from painfree.api import IDEMPOTENCY_HEADER


@pytest.fixture
def world(sqlite_url):
    """Two banks and four password-holding identities. See `basic_world`."""
    yield from basic_world.build(sqlite_url)


# --- authorisation did not change -------------------------------------------

def test_a_basic_member_is_refused_every_route_at_a_bank_it_does_not_hold(world):
    """The access tests' table, imported, driven with a password instead of a
    header.

    Not restated: :data:`test_service_access.PER_CONNECTION` is checked against
    the application's own router by the test that owns it, so importing it is
    what makes this assertion about *every* per-connection route rather than
    about the ones somebody remembered.

    The property is theirs too, unchanged: every route answers a connection
    this caller does not hold exactly as it answers one that was never
    registered.
    """
    client, _, ids = world
    for method, path, body in access.PER_CONNECTION:
        real = access._request(client, method, path, ids, YOURS,
                            mallory(**BROWSER), body)
        invented = access._request(client, method, path, {**ids, **access.NOTHING},
                                "no-such-bank", mallory(**BROWSER), body)
        assert real.status_code in (403, 404), \
            f"{method} {path} reached another connection: {real.status_code}"
        assert real.status_code == invented.status_code, (
            f"{method} {path} answers {real.status_code} for a connection that "
            f"exists and {invented.status_code} for one that does not")


def test_a_basic_member_is_refused_a_write_it_lacks_the_level_for(world):
    """A `viewer` grant does not submit a payment, whatever the credential was."""
    client, app, _ = world
    grant(app, NOBODY, MINE, "viewer")
    response = client.post(
        f"/v1/connections/{MINE}/payments", json=access.payment_body(),
        headers=basic(NOBODY, NOBODY_PASSWORD,
                      **{IDEMPOTENCY_HEADER: "basic-viewer-0001"}))
    assert response.status_code == 403, response.text
    detail = response.json()["error"]["detail"]
    assert detail["missing_scopes"] == ["payments:submit"]
    assert detail["connection_id"] == MINE
    # The same caller reads that connection perfectly well.
    assert client.get(f"/v1/orders/ord_{MINE}",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 200


def test_a_basic_member_cannot_manage_grants_or_accounts(world):
    """Including the accounts table their own credential lives in.

    That is the escalation this mode adds and it is closed the way the last one
    was closed: creating an administrator account is not a scope, so no grant
    carries it and no member can be given it.
    """
    client, app, _ = world
    for method, path, body in (
            ("GET", "/v1/grants", None),
            ("PUT", "/v1/grants", {"subject": MALLORY, "connection_id": YOURS,
                                   "level": "operator"}),
            ("GET", "/v1/accounts", None),
            ("PUT", "/v1/accounts", {"subject": "accomplice",
                                     "password": "accomplice-long-enough",
                                     "role": "admin"}),
            ("PATCH", f"/v1/accounts/{MALLORY}", {"role": "admin"}),
            ("POST", f"/v1/accounts/{ROOT}/password",
             {"password": "taking-over-this-deployment"}),
            ("DELETE", f"/v1/accounts/{ROOT}", None),
            ("GET", "/v1/lockouts", None),
            ("DELETE", f"/v1/lockouts/subject/{MALLORY}", None)):
        response = client.request(method, path, headers=mallory(),
                                  json=body) if body else client.request(
            method, path, headers=mallory())
        assert response.status_code == 403, f"{method} {path}: {response.text}"
        assert response.json()["error"]["detail"]["required_role"] == "admin"
    # Nothing moved: `mallory` is still a member and `root` still signs in.
    assert client.get("/auth/me", headers=mallory()).json()["role"] == "member"
    assert client.get("/auth/me", headers=root()).status_code == 200
    assert {row["subject"] for row
            in client.get("/v1/accounts", headers=root()).json()["accounts"]} \
        == {ROOT, MALLORY, WATCHER, NOBODY}
    # And the console pages are refused too, which is a second surface.
    for path in ("/ui/access", "/ui/accounts"):
        assert client.get(path, headers=mallory(**BROWSER)).status_code == 403


def test_an_oversight_holder_authenticated_by_basic_writes_nothing(world):
    """The oversight tests' write-route enumeration, imported, driven with a
    password.

    Read off the router by the module that owns it, so this covers the routes
    this mode added as well -- `PUT /v1/accounts` and
    `DELETE /v1/lockouts/{scope}/{value}` are write routes by that definition
    and are attacked here without anybody having listed them.
    """
    client, app, ids = world
    reached = []
    for method, path in sorted(oversight.write_routes(app)):
        response = oversight._attack(client, method, path, ids, watcher())
        if response.status_code != 403:
            reached.append(f"{method} {path} -> {response.status_code}")
    assert not reached, (
        "an oversight grant is read-only whatever credential established it, "
        "and these routes did not refuse it: " + "; ".join(reached))
    # The reach it *does* have is unchanged, so this is not passing because the
    # credential stopped working.
    assert client.get(f"/v1/orders/ord_{YOURS}",
                      headers=watcher()).status_code == 200
    assert len(client.get("/v1/webhooks",
                          headers=watcher()).json()["webhooks"]) == 3
    # And nothing the 45-odd write routes could have done happened.
    assert len(client.get("/v1/accounts",
                          headers=root()).json()["accounts"]) == 4
    assert client.get("/v1/grants?subject=wanda",
                      headers=root()).json()["grants"] == []


def test_revoking_a_grant_takes_effect_on_the_next_basic_request(world):
    """Grants are read per request, not copied into the credential.

    A password is a long-lived credential in a way a session is not, so this is
    the property that stops it also being long-lived *authorisation*.

    `nobody` is given both banks so that revoking one leaves them still holding
    `payments:read` somewhere: the refusal is then the object-level `404` that
    per-connection grants are about, rather than the route-level `403` a caller
    who now holds nothing at all would get.
    """
    client, app, _ = world
    for connection_id in (MINE, YOURS):
        grant(app, NOBODY, connection_id, "viewer")
    for connection_id in (MINE, YOURS):
        assert client.get(f"/v1/orders/ord_{connection_id}",
                          headers=basic(NOBODY, NOBODY_PASSWORD)
                          ).status_code == 200
    assert client.delete(f"/v1/grants/{NOBODY}/{MINE}",
                         headers=root()).status_code == 200
    assert client.get(f"/v1/orders/ord_{MINE}",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 404
    assert client.get(f"/v1/orders/ord_{YOURS}",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 200
    # And the last grant going leaves them refused at the route level instead,
    # because they now hold the scope nowhere at all.
    assert client.delete(f"/v1/grants/{NOBODY}/{YOURS}",
                         headers=root()).status_code == 200
    assert client.get(f"/v1/orders/ord_{YOURS}",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 403


def test_suspending_an_account_takes_effect_on_the_next_request(world):
    """The account row is read on every request, so this needs no restart."""
    client, app, _ = world
    assert client.get("/auth/me", headers=mallory()).status_code == 200
    assert client.patch(f"/v1/accounts/{MALLORY}", json={"disabled": True},
                        headers=root()).status_code == 200
    assert client.get("/auth/me", headers=mallory()).status_code == 401


def test_changing_a_password_invalidates_the_old_one_immediately(world):
    """The verification cache is keyed by the stored hash, so it cannot outlive it.

    Signing in first is deliberate: it puts the old credential *in* the cache,
    so a cache that survived a password change would make this test pass with
    the old password.
    """
    client, app, _ = world
    assert client.get("/auth/me", headers=mallory()).status_code == 200
    assert client.post(f"/v1/accounts/{MALLORY}/password",
                       json={"password": "a-brand-new-long-password"},
                       headers=root()).status_code == 200
    assert client.get("/auth/me", headers=mallory()).status_code == 401
    assert client.get("/auth/me", headers=basic(
        MALLORY, "a-brand-new-long-password")).status_code == 200


def test_deleting_an_account_keeps_the_grants_and_says_so(world):
    """Two decisions, and the response does not pretend they are one."""
    client, app, _ = world
    response = client.delete(f"/v1/accounts/{MALLORY}", headers=root())
    assert response.status_code == 200
    assert response.json()["grants_retained"] is True
    assert client.get("/auth/me", headers=mallory()).status_code == 401
    assert [row["connection_id"] for row in client.get(
        f"/v1/grants?subject={MALLORY}", headers=root()).json()["grants"]] == [MINE]
    assert client.delete(f"/v1/accounts/{MALLORY}",
                         headers=root()).status_code == 404


