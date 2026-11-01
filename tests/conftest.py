import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session", autouse=True)
def _seed_sample_pcaps():
    """把测试用 pcap 复制到 data/pcaps/samples，避免测试依赖未跟踪的数据。

    为什么需要：`data/` 不进 git，干净 clone 出来的仓库没有样本 pcap，
    流量相关接口测试会全红（CI 上就是这样）。样本本身只有 64KB，
    已经作为测试固件放在 tests/fixtures/pcaps/。
    """
    import shutil

    from app.settings import get_settings

    src = Path(__file__).parent / "fixtures" / "pcaps"
    dst = get_settings().pcaps_dir / "samples"
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.glob("*.pcap"):
        target = dst / f.name
        if not target.exists() or target.stat().st_size != f.stat().st_size:
            shutil.copy2(f, target)
