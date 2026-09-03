"""A normalised `camt` statement as the rows of a statement page.

Pure arithmetic over the normalised statement shape, so the tests are about the
three things a running balance can get wrong: the direction, the entries it
must not count, and the money it must not lose.

**The fixture's amounts are chosen to break floats.** `0.10 + 0.20` is `0.30`
in decimal and `0.30000000000000004` in a binary double, and the closing
balance is the opening balance plus those two credits minus the debit. The
equality below holds exactly in `Decimal` and fails in `float`, which is what
makes it worth asserting rather than assuming.
"""

from __future__ import annotations

import decimal

from conftest import fixture_bytes
from painfree.statements import normalise
from painfree.ui import ledger


def _payload() -> dict:
    return normalise(fixture_bytes("camt.053.001.08"))[0].payload


D = decimal.Decimal


def test_the_running_balance_is_the_opening_balance_plus_the_entries():
    book = ledger.read(_payload(), opening=D("1000.00"), closing=D("-2949.45"))
    assert [line.balance for line in book.booked] == [
        D("-2949.75"), D("-2949.65"), D("-2949.45")]
    assert book.running is True
    assert book.reconciles is True


def test_the_two_directions_are_two_columns_and_two_totals():
    book = ledger.read(_payload(), opening=D("1000.00"))
    assert [line.credit for line in book.booked] == [False, True, True]
    assert book.debited == D("3949.75") and book.debits == 1
    assert book.credited == D("0.30") and book.credits == 2


def test_with_no_opening_balance_there_is_no_column_rather_than_a_guess():
    """A column of numbers all wrong by the same amount is worse than none."""
    book = ledger.read(_payload())
    assert book.running is False
    assert all(line.balance is None for line in book.booked)
    assert book.reconciles is None, "not checked and does not add up differ"


def test_a_statement_that_does_not_add_up_says_so():
    book = ledger.read(_payload(), opening=D("1000.00"), closing=D("-2949.44"))
    assert book.reconciles is False


def test_an_entry_the_bank_has_not_booked_does_not_move_the_balance():
    """`PDNG` is money the bank has seen. A balance including it matches none."""
    payload = _payload()
    payload["entries"][1]["status"] = "PDNG"
    book = ledger.read(payload, opening=D("1000.00"))
    assert len(book.pending) == 1 and len(book.booked) == 2
    assert book.pending[0].balance is None
    assert [line.balance for line in book.booked] == [D("-2949.75"), D("-2949.55")]
    assert book.credited == D("0.20"), "and it is not in the totals either"


def test_the_message_ids_the_entries_name_are_the_ones_worth_looking_up():
    assert ledger.message_ids(_payload()) == {"PF3868D16485F403EA96B3AF3B78F98E6"}


def test_an_entry_naming_one_of_our_messages_carries_its_order():
    book = ledger.read(_payload(), opening=D("1000.00"),
                       orders={"PF3868D16485F403EA96B3AF3B78F98E6": "ord_1"})
    assert book.booked[0].order_id == "ord_1"
    assert book.ours == 1
    assert [line.order_id for line in book.booked[1:]] == [None, None]


def test_a_filter_hides_rows_and_does_not_recompute_the_balance():
    """A filtered statement still shows the account's real balance."""
    book = ledger.read(_payload(), opening=D("1000.00"),
                       orders={"PF3868D16485F403EA96B3AF3B78F98E6": "ord_1"})
    assert [line.balance for line in book.showing("credit")] == [
        D("-2949.65"), D("-2949.45")]
    assert [line.balance for line in book.showing("debit")] == [D("-2949.75")]
    assert [line.order_id for line in book.showing("ours")] == ["ord_1"]
    assert book.showing("nonsense") == book.booked


def test_an_amount_that_will_not_parse_is_lost_from_the_total_not_from_the_page():
    """A display path never raises. A row with no amount is still a row."""
    payload = _payload()
    payload["entries"][0]["amount"] = "not money"
    book = ledger.read(payload, opening=D("1000.00"))
    assert len(book.booked) == 3
    assert book.booked[0].amount is None
    assert book.debited == D(0)


def test_what_a_row_says_about_itself_comes_from_the_transaction_under_it():
    line = ledger.read(_payload(), opening=D("1000.00")).booked[0]
    assert line.counterparty["name"] == "Robert Schneider AG"
    assert line.counterparty["iban"] == "CH4431999123000889012"
    assert line.reference == {"type": "QRR",
                              "reference": "210000000003139471430009017"}
    # The most specific thing said about it: the transaction's own line, not
    # the entry's `AddtlNtryInf`.
    assert line.description == "Rechnung 2026-0242"
    assert line.batch == 1
