"""Tests for FastAPI route decoration scanning (comment / false-positive guards)."""

from __future__ import annotations

from depos.enrichment.http_probes import scan_fastapi_routes


def test_scan_skips_decorators_in_full_line_hash_comments():
    source = """# @router.get("/repos"), @app.post("/x", status_code=201), etc.
@router.get("/real")
def handler():
    pass
"""
    decs = scan_fastapi_routes(source, file="x.py")
    assert len(decs) == 1
    assert decs[0].route_pattern == "/real"
    assert decs[0].handler_name == "handler"


def test_scan_skips_decorators_after_inline_hash_comment():
    source = """pass  # @router.get("/fake")
@router.post("/real")
def handler():
    pass
"""
    decs = scan_fastapi_routes(source, file="x.py")
    assert len(decs) == 1
    assert decs[0].route_pattern == "/real"
    assert decs[0].http_method == "POST"


def test_hash_inside_string_does_not_hide_real_decorator():
    source = """hint = "# not a comment"
@router.get("/real")
def handler():
    pass
"""
    decs = scan_fastapi_routes(source, file="x.py")
    assert len(decs) == 1
    assert decs[0].route_pattern == "/real"
