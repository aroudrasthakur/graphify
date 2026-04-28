"""Test HTTP method extraction from fetch and axios calls.

This test verifies that http_probes.py correctly extracts HTTP methods
from various fetch and axios call patterns to ensure proper route matching.
"""
from __future__ import annotations

from depos.enrichment.http_probes import scan_ts_http_calls


def test_fetch_with_explicit_method():
    """Test fetch() with explicit method in options object."""
    source = """
async function createRepo() {
  const res = await fetch('/api/repos', {
    method: 'POST',
    body: JSON.stringify({ name: 'test' })
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"
    assert sites[0].method_inferred == False
    assert sites[0].kind == "fetch"


def test_fetch_with_double_quotes_method():
    """Test fetch() with double quotes around method."""
    source = """
async function updateRepo() {
  const res = await fetch("/api/repos/1", {
    method: "PUT"
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "PUT"
    assert sites[0].method_inferred == False


def test_fetch_without_method_no_options():
    """Test fetch() without options defaults to GET."""
    source = """
async function getRepos() {
  const res = await fetch('/api/repos');
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "GET"
    assert sites[0].method_inferred == True


def test_fetch_with_options_but_no_method():
    """Test fetch() with options object but no method field."""
    source = """
async function getRepos() {
  const res = await fetch('/api/repos', {
    headers: { 'Authorization': 'Bearer token' }
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    # When options exist but no method, should be None (not inferred)
    assert sites[0].http_method is None
    assert sites[0].method_inferred == True


def test_axios_get_method():
    """Test axios.get() extracts GET method."""
    source = """
async function getRepos() {
  const res = await axios.get('/api/repos');
  return res.data;
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "GET"
    assert sites[0].method_inferred == False
    assert sites[0].kind == "axios"


def test_axios_post_method():
    """Test axios.post() extracts POST method."""
    source = """
async function createRepo(data) {
  const res = await axios.post('/api/repos', data);
  return res.data;
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "POST"
    assert sites[0].method_inferred == False


def test_axios_without_method():
    """Test axios() without method defaults to GET."""
    source = """
async function getRepos() {
  const res = await axios('/api/repos');
  return res.data;
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "GET"
    # UPDATED: When axios() is called without method prefix and no config,
    # the method is inferred as GET (method_inferred=True)
    assert sites[0].method_inferred == True


def test_multiple_calls_different_methods():
    """Test multiple HTTP calls with different methods in same file."""
    source = """
async function repoOperations() {
  const list = await fetch('/api/repos');
  const created = await fetch('/api/repos', { method: 'POST' });
  const updated = await axios.put('/api/repos/1');
  const deleted = await axios.delete('/api/repos/1');
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 4
    
    # First fetch - GET (inferred)
    assert sites[0].http_method == "GET"
    assert sites[0].method_inferred == True
    
    # Second fetch - POST (explicit)
    assert sites[1].http_method == "POST"
    assert sites[1].method_inferred == False
    
    # Third - axios.put
    assert sites[2].http_method == "PUT"
    assert sites[2].method_inferred == False
    
    # Fourth - axios.delete
    assert sites[3].http_method == "DELETE"
    assert sites[3].method_inferred == False


def test_fetch_method_with_spaces():
    """Test fetch() with various spacing around method."""
    source = """
async function test1() {
  await fetch('/api/1', { method : 'POST' });
  await fetch('/api/2', { method: "DELETE" });
  await fetch('/api/3', {method:'PATCH'});
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 3
    assert sites[0].http_method == "POST"
    assert sites[1].http_method == "DELETE"
    assert sites[2].http_method == "PATCH"


def test_fetch_with_template_literal_and_method():
    """Test fetch() with template literal URL and explicit method."""
    source = """
async function updateRepo(id: string) {
  const res = await fetch(`/api/repos/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ name: 'updated' })
  });
  return res.json();
}
"""
    sites = scan_ts_http_calls(source, file="test.ts")
    assert len(sites) == 1
    assert sites[0].http_method == "PUT"
    assert sites[0].method_inferred == False
    assert sites[0].is_dynamic_url == True
    assert sites[0].url_literal == "/api/repos/${id}"
