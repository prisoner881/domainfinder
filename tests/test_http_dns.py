import respx

from domainfinder.cache import Cache
from domainfinder.dns import Resolver
from domainfinder.http import Http, _parse_retry_after


def test_retry_after_parsing():
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after("9999") == 60.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("garbage") is None


@respx.mock
async def test_retries_on_429_honouring_retry_after(tmp_path):
    route = respx.get("https://crt.sh/").mock(side_effect=[
        __import__("httpx").Response(429, headers={"Retry-After": "0"}),
        __import__("httpx").Response(200, json=[{"id": 1}]),
    ])
    http = Http(cache=Cache(tmp_path / "c.sqlite", 3600))
    r = await http.get("https://crt.sh/", params={"q": "zdp.com"})
    assert r.ok and r.json() == [{"id": 1}]
    assert route.call_count == 2
    # second call is served from the cache
    r2 = await http.get("https://crt.sh/", params={"q": "zdp.com"})
    assert r2.json() == [{"id": 1}] and route.call_count == 2
    await http.aclose()


@respx.mock
async def test_fetch_page_records_redirect_chain():
    respx.get("http://myzdp.com/").respond(301, headers={"Location": "https://my.zdp.com/"})
    respx.get("https://my.zdp.com/").respond(302, headers={"Location": "/login"})
    respx.get("https://my.zdp.com/login").respond(200, text="<title>MyZDP</title>")
    http = Http()
    hops, resp = await http.fetch_page("http://myzdp.com/")
    assert [h.url for h in hops] == ["http://myzdp.com/", "https://my.zdp.com/", "https://my.zdp.com/login"]
    assert resp.status == 200 and "MyZDP" in resp.text
    await http.aclose()


@respx.mock
async def test_doh_answers_nxdomain_and_mx():
    def doh(request):
        name, rtype = request.url.params["name"], request.url.params["type"]
        import httpx
        if name == "zdpemployment.com":
            return httpx.Response(200, json={"Status": 3})
        if rtype == "MX":
            return httpx.Response(200, json={"Status": 0, "Answer": [
                {"name": "zdp.com.", "type": 15, "data": "10 mxa-0099aa01.gslb.pphosted.com."}]})
        if rtype == "TXT":
            return httpx.Response(200, json={"Status": 0, "Answer": [
                {"name": "zdp.com.", "type": 16, "data": "\"v=spf1 include:_spf.zdp.com\" \" ~all\""}]})
        return httpx.Response(200, json={"Status": 0, "Answer": [
            {"name": "www.zdp.com.", "type": 5, "data": "www.zdp.com.edgekey.net."}]})

    respx.get("https://dns.google/resolve").mock(side_effect=doh)
    http = Http()
    res = Resolver(http, mode="doh")
    assert (await res.query("zdpemployment.com", "NS")).status == "nxdomain"
    mx = await res.query("zdp.com", "MX")
    assert mx.records == ["10 mxa-0099aa01.gslb.pphosted.com"]
    txt = await res.query("zdp.com", "TXT")
    assert txt.records == ["v=spf1 include:_spf.zdp.com ~all"]
    a = await res.query("www.zdp.com", "A")  # only a CNAME in the answer → nodata
    assert a.status == "nodata"
    await http.aclose()
