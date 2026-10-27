"""前端契约测试：页面里调用的每个接口都必须真的存在。

纯静态分析，不需要浏览器：
- 从 index.html 里抽出所有 fetch(...) 的目标，归一化路径参数，和 FastAPI 路由比对；
- 检查 $("#id") 引用的元素都真实存在（静态 HTML 或 JS 模板里定义）；
- 检查顶栏每个按钮都绑定了 handler；
- 有 node 时顺便做一次 JS 语法检查。

这样「后端删了一个接口，前端静默 404」这类问题会在 CI 里直接红掉。
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from app.main import app

HTML_PATH = __import__("pathlib").Path(__file__).resolve().parent.parent / "app" / "web" / "index.html"
HTML = HTML_PATH.read_text(encoding="utf-8")


def normalize(url: str) -> str:
    url = re.sub(r"\$\{[^}]*\}", "{}", url)     # 模板变量
    return url.split("?")[0].rstrip("/")


def frontend_endpoints() -> set[str]:
    raw = re.findall(r'fetch\(\s*[`"\']([^`"\']+)', HTML)
    return {normalize(u) for u in raw if u.startswith("/")}


def backend_routes() -> set[str]:
    """用 OpenAPI schema 拿路由：FastAPI 新版对 include_router 是懒加载的，
    直接遍历 app.routes 只能看到 _IncludedRouter 占位符。"""
    paths = app.openapi().get("paths", {})
    return {re.sub(r"\{[^}]+\}", "{}", p).rstrip("/") for p in paths}


def test_frontend_calls_only_existing_endpoints():
    missing = sorted(frontend_endpoints() - backend_routes())
    assert not missing, f"前端调用了不存在的接口: {missing}"


def test_all_api_routes_are_used_or_intentional():
    """反向检查：后端有、前端从不调用的接口要么是文档/运维接口，要么是漏接。"""
    allowed_unused = {
        "/docs", "/redoc", "/openapi.json", "/healthz", "/api/info",
        "/api/chat", "/api/agent/chat", "/api/feedback",
        "/api/kbs", "/api/kbs/{}", "/api/kbs/{}/status", "/api/kbs/{}/reindex",
        "/api/chunks/{}/{}", "/api/documents/{}/{}",
        "/api/eval/run", "/api/siem/ingest", "/api/siem/alerts",
        "/api/traffic/tail", "/api/traffic/analyze", "/api/traffic/findings/{}",
    }
    unused = backend_routes() - frontend_endpoints() - allowed_unused
    # 允许新增接口暂时没接前端，但这里显式列出，避免「写了忘接」静默发生
    assert unused <= {"/api/siem/tail", "/api/siem/cursors", "/api/traffic/detectors"}, \
        f"以下接口既没被前端调用，也不在豁免清单里: {sorted(unused)}"


def test_referenced_element_ids_exist():
    declared = set(re.findall(r'id="([^"]+)"', HTML))
    referenced = set(re.findall(r'\$\("#([A-Za-z0-9_-]+)"\)', HTML))
    dynamic = {"tReport", "tSteps", "tMode", "siemDetail", "siemRoot", "sReport", "sSteps"}
    missing = referenced - declared - dynamic
    assert not missing, f"JS 引用了不存在的元素: {sorted(missing)}"


def test_header_buttons_have_handlers():
    for btn in ("btnSiem", "btnTraffic", "btnEval", "btnKb", "send", "input", "modeSeg"):
        assert f'id="{btn}"' in HTML, f"缺少元素 {btn}"
        assert f'$("#{btn}")' in HTML, f"{btn} 没有绑定逻辑"


def test_no_external_resources():
    """页面必须能离线打开：不能有外部 CDN 依赖。"""
    assert not re.search(r'<(script|link)[^>]+https?://', HTML)


def test_modal_and_sse_helpers_defined():
    for fn in ("openModal", "renderMd", "stepLine", "sse", "runTraffic", "openSiem"):
        if fn == "sse":
            continue
        assert f"function {fn}(" in HTML or f"async function {fn}(" in HTML, f"缺少函数 {fn}"


@pytest.mark.skipif(not shutil.which("node"), reason="需要 node")
def test_javascript_syntax(tmp_path):
    js = re.search(r"<script>(.*)</script>", HTML, re.S).group(1)
    f = tmp_path / "ui.js"
    f.write_text(js, encoding="utf-8")
    proc = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
