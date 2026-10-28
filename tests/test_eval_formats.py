"""数据集格式层：一个转换器对应一种格式，新增数据集不该改评测代码。"""


from app.eval.formats import (
    detect_format,
    flow_metrics,
    load_flows,
    normalize_malicious,
)

ZEEK = """#separator \\x09
#set_separator\t,
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\tlabel
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tstring
1557872523.1\tC1\t192.168.100.103\t43478\t85.93.226.122\t6667\ttcp\t1.2\tC&C
1557872530.2\tC2\t192.168.100.103\t43479\t85.93.226.122\t6667\ttcp\t1.1\tC&C-HeartBeat
1557872540.3\tC3\t192.168.100.103\t52000\t8.8.8.8\t53\tudp\t0.1\tBenign
1557872550.4\tC4\t192.168.100.103\t52001\t1.1.1.1\t443\ttcp\t0.4\t-
"""


def test_detect_format_by_header(tmp_path):
    z = tmp_path / "conn.labeled"
    z.write_text(ZEEK)
    assert detect_format(z) == "zeek_conn"

    b = tmp_path / "cap.binetflow"
    b.write_text("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n")
    assert detect_format(b) == "binetflow"

    c = tmp_path / "flows.csv"
    c.write_text("src,sport,dst,dport,label\n")
    assert detect_format(c) == "csv"


def test_zeek_conn_parsing_and_labels(tmp_path):
    z = tmp_path / "conn.labeled"
    z.write_text(ZEEK)
    fmt, flows = load_flows(z)
    rows = list(flows)
    assert fmt == "zeek_conn"
    assert [(r.src, r.sport, r.dst, r.dport) for r in rows] == [
        ("192.168.100.103", 43478, "85.93.226.122", 6667),
        ("192.168.100.103", 43479, "85.93.226.122", 6667),
        ("192.168.100.103", 52000, "8.8.8.8", 53),
    ], "label 为 - 的行（未标注）要跳过"
    assert [r.malicious for r in rows] == [True, True, False]
    assert rows[0].start_ts > 1.5e9


def test_label_normalization_covers_common_spellings():
    for label in ["flow=From-Botnet-V42-TCP", "C&C", "C&C-HeartBeat", "Malicious", "attack", "PartOfAHorizontalPortScan"]:
        assert normalize_malicious(label) is True, label
    for label in ["flow=Background", "Benign", "normal", "-", "", "0"]:
        assert normalize_malicious(label) is False, label


def test_generic_csv_with_column_mapping(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("SrcAddr,Sport,DstAddr,Dport,Label\n10.0.0.1,1234,10.0.0.2,80,Botnet\n")
    fmt, flows = load_flows(p, fmt="csv", columns={
        "src": "SrcAddr", "sport": "Sport", "dst": "DstAddr", "dport": "Dport", "label": "Label",
    })
    rows = list(flows)
    assert fmt == "csv" and len(rows) == 1
    assert rows[0].malicious and rows[0].dst == "10.0.0.2"


def test_metrics_work_on_any_format(tmp_path):
    z = tmp_path / "conn.labeled"
    z.write_text(ZEEK)
    _, flows = load_flows(z)
    m = flow_metrics(flows, {("192.168.100.103", 43478, "85.93.226.122", 6667)})
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 0, 1)


def test_zeek_conn_handles_space_joined_label_columns(tmp_path):
    """IoT-23 的标注脚本把最后三列用三个空格追加，而不是 TAB（实测撞到过）。

    不处理的话 label 会被解析成 `(empty)   Malicious   C&C`，恶意/正常全判错。
    """
    header = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\ttunnel_parents   label   detailed-label\n"
        "#types\ttime\taddr\tport\taddr\tport\tstring   string   string\n"
    )
    rows = [
        "1526756261.86\t192.168.2.5\t38792\t200.168.87.203\t59353\t(empty)   Malicious   PartOfAHorizontalPortScan",
        "1526756268.87\t192.168.2.5\t38792\t8.8.8.8\t53\t(empty)   Benign   -",
    ]
    z = tmp_path / "conn.labeled"
    z.write_text(header + "\n".join(rows) + "\n")
    _, flows = load_flows(z)
    got = list(flows)
    assert [f.label for f in got] == ["Malicious", "Benign"]
    assert [f.malicious for f in got] == [True, False]
    assert got[0].dport == 59353
