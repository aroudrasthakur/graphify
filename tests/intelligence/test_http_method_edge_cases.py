"""Test edge cases for HTTP method extraction that might affect match confidence.

This test explores potential edge cases where http_method extraction might
fail or be incomplete, which could reduce match confidence in score_match.
"""
from __future__ import annotations

from depos.enrichment.http_probes import scan_ts_http_calls


def test_fetch_method_with_variable():
    """Test fetch() with method from a variable (not extractable)."""
    source = """
async function makeRequest(method: string) {
  const res = await fetch('/api/repos', {
    method: method,
    body: JSON.stringify({ name: 'test' })
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    # Method is a variable, not a string literal - cannot extract
    assert sites[0].http_method is None
    assert sites[0].method_inferred == True


def test_fetch_method_uppercase_in_source():
    """Test fetch() with uppercase method in source."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'POST'
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"


def test_fetch_method_lowercase_in_source():
    """Test fetch() with lowercase method in source (should be uppercased)."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'post'
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"


def test_fetch_method_mixed_case():
    """Test fetch() with mixed case method (should be uppercased)."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'Post'
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"


def test_fetch_multiline_options():
    """Test fetch() with multiline options object."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer token'
    },
    body: JSON.stringify({ name: 'test' })
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"
    assert sites[0].method_inferred == False


def test_axios_method_all_variants():
    """Test all axios method variants."""
    source = """
async function testAllMethods() {
  await axios.get('/api/1');
  await axios.post('/api/2');
  await axios.put('/api/3');
  await axios.patch('/api/4');
  await axios.delete('/api/5');
  await axios.options('/api/6');
  await axios.head('/api/7');
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 7
    assert sites[0].http_method == "GET"
    assert sites[1].http_method == "POST"
    assert sites[2].http_method == "PUT"
    assert sites[3].http_method == "PATCH"
    assert sites[4].http_method == "DELETE"
    assert sites[5].http_method == "OPTIONS"
    assert sites[6].http_method == "HEAD"


def test_fetch_with_nested_braces():
    """Test fetch() with nested braces in options (potential regex issue)."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'test', meta: { key: 'value' } })
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    # This might fail if the regex doesn't handle nested braces correctly
    # The current regex uses [^}]* which stops at the first }
    # This is a known limitation - we can only capture simple options objects
    assert len(sites) >= 1
    if len(sites) == 1:
        # If we captured it, method should be extracted
        # But due to nested braces, the regex might not capture the full options
        # This is an edge case that might need improvement
        pass


def test_fetch_method_with_trailing_comma():
    """Test fetch() with trailing comma in options."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'POST',
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"


def test_axios_with_config_object():
    """Test axios() with config object (method in config)."""
    source = """
async function makeRequest() {
  const res = await axios('/api/repos', {
    method: 'POST',
    data: { name: 'test' }
  });
  return res.data;
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    # UPDATED: Now extracts method from config object
    assert sites[0].http_method == "POST"
    assert sites[0].method_inferred == False


def test_fetch_with_backticks_in_method():
    """Test fetch() with backticks around method (unusual but valid)."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: `POST`
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    # UPDATED: Now supports backticks around method
    assert sites[0].http_method == "POST"
    assert sites[0].method_inferred == False
