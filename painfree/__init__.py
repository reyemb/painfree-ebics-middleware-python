"""painfree -- JSON in, EBICS out.

The service layer lives directly under this package; the EBICS 3.0 protocol
engine is the subpackage :mod:`painfree.ebics3`, which must not import from any
other part of ``painfree``. This module is deliberately empty apart from the
version, so that importing the engine does not drag FastAPI, SQLAlchemy or a
database driver in with it -- that is what keeps the engine releasable on its
own.
"""

from __future__ import annotations

__version__ = "0.7.0"

__all__ = ["__version__"]
