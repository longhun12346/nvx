"""Real-VM acceptance for the Ubuntu workload profile and shared session storage."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar, vmm_processes
from runtime_assets import artifact_args


WORKLOAD = r'''
import importlib, json, os, ssl, subprocess, urllib.request, warnings
from pathlib import Path
names = "pandas numpy scipy sklearn matplotlib mplfinance pyecharts networkx openpyxl docx pptx pypdf pdfplumber pdf2image pypdfium2 reportlab pytesseract PIL markitdown rdkit yaml frontmatter rich plotille requests playwright pip".split()
for name in names: importlib.import_module(name)
from importlib.metadata import version
from pip._vendor.packaging.requirements import Requirement
profile = json.loads(Path("/usr/share/nvx/workloads.json").read_text())
for text in profile["requirements"]:
    requirement = Requirement(text)
    assert requirement.specifier.contains(version(requirement.name)), text
import plotille
assert version("plotille") == "5.0.0"
assert plotille.plot([0,1,2],[0,1,4])
assert ssl.create_default_context().cert_store_stats()["x509_ca"] > 50
for url in ("https://example.com", "https://pypi.org/simple/", "https://github.com"):
    with urllib.request.urlopen(url, timeout=30) as r: assert r.status == 200
for command in (["curl", "--fail", "--max-time", "30", "-o", "/dev/null", "https://example.com"],
                ["wget", "-T", "30", "-O", "/dev/null", "https://example.com"],
                ["npm", "--version"], ["python3", "-m", "pip", "--version"]):
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=45)
assert "WenQuanYi" in subprocess.check_output(["fc-list"], text=True)
subprocess.run(["python3", "-m", "venv", "--system-site-packages", "/home/session/test-venv"], check=True)
subprocess.run(["/home/session/test-venv/bin/python", "-m", "pip", "--version"], check=True, capture_output=True)
subprocess.run(["/home/session/test-venv/bin/python", "-c", "import pandas,docx"], check=True)
import numpy as np, pandas as pd, scipy.stats
assert scipy.stats.linregress([1,2,3],[2,4,6]).slope == 2
assert pd.DataFrame({"x":[1,2,3]}).x.sum() == 6
from sklearn.linear_model import LinearRegression
assert abs(LinearRegression().fit(np.array([[1],[2],[3]]),np.array([2,4,6])).coef_[0]-2)<1e-6
from rdkit import Chem
assert Chem.MolFromSmiles("CCO").GetNumAtoms() == 3
title = "\u4e2d\u6587\u6587\u6863\u9a8c\u8bc1"
from docx import Document
d=Document();d.add_heading(title);d.add_paragraph("NVX document workload");d.save("/workspace/test.docx")
assert Document("/workspace/test.docx").paragraphs[0].text == title
from openpyxl import Workbook, load_workbook
w=Workbook();w.active.append([title,1,2]);w.active["D1"]="=SUM(B1:C1)";w.save("/workspace/test.xlsx")
assert load_workbook("/workspace/test.xlsx").active["A1"].value == title
from pptx import Presentation
p=Presentation();p.slides.add_slide(p.slide_layouts[0]).shapes.title.text=title;p.save("/workspace/test.pptx")
assert Presentation("/workspace/test.pptx").slides[0].shapes.title.text == title
import matplotlib.pyplot as plt
with warnings.catch_warnings(record=True) as seen:
    warnings.simplefilter("always")
    plt.plot([1,2,3],[2,4,6]);plt.title(title);plt.savefig("/workspace/chart.png");plt.close()
    assert not [str(w.message) for w in seen if "Glyph" in str(w.message)]
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
pdfmetrics.registerFont(TTFont("CJK","/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"))
c=canvas.Canvas("/workspace/test.pdf");c.setFont("CJK",18);c.drawString(40,780,title);c.save()
from pypdf import PdfReader
assert title in PdfReader("/workspace/test.pdf").pages[0].extract_text()
import pypdfium2
pdf=pypdfium2.PdfDocument("/workspace/test.pdf")
pdf[0].render(scale=1).to_pil().save("/workspace/pdf-preview.png")
Path("/home/session/private-marker").write_text("private")
print(json.dumps({"imports":names,"caCount":ssl.create_default_context().cert_store_stats()["x509_ca"],
                  "cpus":os.cpu_count(),"documents":True,"https":True,"venv":True}))
'''

NODE_WORKLOAD = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
(async () => {
  const profile = JSON.parse(fs.readFileSync('/usr/share/nvx/workloads.json', 'utf8'));
  const names = Object.keys(profile.node.dependencies);
  for (const name of names) {
    assert(name === 'oh-my-mermaid' ? await import(name) : require(name));
  }
  const echarts = require('echarts');
  const chart = echarts.init(null, null, {renderer:'svg', ssr:true, width:480, height:320});
  chart.setOption({xAxis:{type:'category',data:['A','B']}, yAxis:{}, series:[{type:'bar',data:[2,4]}]});
  const svg = chart.renderToSVGString();
  chart.dispose();
  assert(svg.includes('<svg'));
  fs.writeFileSync('/workspace/node-chart.svg', svg);
  const sharp = require('sharp');
  await sharp(Buffer.from(svg)).png().toFile('/workspace/node-chart.png');
  assert.equal((await sharp('/workspace/node-chart.png').metadata()).width, 480);
  assert.equal(typeof require('@antv/g2').Chart, 'function');
  const React = require('react');
  const {renderToStaticMarkup} = require('react-dom/server');
  const {FaCheck} = require('react-icons/fa');
  assert(renderToStaticMarkup(React.createElement(FaCheck)).includes('<svg'));
  const PptxGenJS = require('pptxgenjs');
  const pptx = new PptxGenJS();
  pptx.addSlide().addText('NVX workload', {x:1,y:1,w:5,h:1});
  await pptx.writeFile({fileName:'/workspace/node-test.pptx'});
  assert(fs.statSync('/workspace/node-test.pptx').size > 1000);
  assert(execFileSync('omm', ['--help'], {encoding:'utf8'}).includes('omm'));
  fs.writeFileSync('/workspace/esm-check.mjs',
    names.filter(name => name !== '@antv/g2')
      .map(name => `import * as m${names.indexOf(name)} from ${JSON.stringify(name)};`).join('\n') +
    '\nimport {createRequire} from "node:module";createRequire(import.meta.url)("@antv/g2");' +
    '\nconsole.log("esm-ok");\n');
  assert(execFileSync('node', ['/workspace/esm-check.mjs'], {encoding:'utf8'}).includes('esm-ok'));
  fs.writeFileSync('/tmp/nvx-resolve.cjs', 'require("sharp");console.log("tmp-ok")');
  assert(execFileSync('node', ['/tmp/nvx-resolve.cjs'], {encoding:'utf8'}).includes('tmp-ok'));
  console.log(JSON.stringify({packages:names, sharp:true, echarts:true, pptx:true, react:true, esm:true}));
})().catch(error => {console.error(error); process.exitCode=1;});
'''

STORAGE = r'''
import errno,json,os
from pathlib import Path
expected=EXPECTED
paths=("/","/tmp","/home","/dev/shm")
stats={p:os.statvfs(p) for p in paths}
assert all(s.f_blocks*s.f_frsize == expected*1024*1024 for s in stats.values()),stats
before=os.statvfs("/home").f_bavail
p=Path("/tmp/quota-probe")
try:
    with p.open("wb") as f:
        for _ in range(min(40,expected//2)): f.write(b"x"*(1024*1024))
    assert os.statvfs("/home").f_bavail < before
    try:
        with p.open("ab") as f:
            for _ in range(expected): f.write(b"x"*(1024*1024))
    except OSError as e:
        assert e.errno == errno.ENOSPC, e
    else: raise AssertionError("session tmpfs exceeded its quota")
finally: p.unlink(missing_ok=True)
assert os.statvfs("/tmp").f_bavail > expected*1024*1024//4096//2
print(json.dumps({"storageMiB":expected,"sharedQuota":True,"enospc":True}))
'''


def run(args, memory, output):
    with tempfile.TemporaryDirectory(prefix="nvxd-workloads-") as temporary:
        root = Path(temporary)
        for name in ("a", "b"):
            (root / name).mkdir()
        command = [str(args.nvxd), *artifact_args(args.repo, args.initrd),
                   "--cpu-profile", "host", "--processors", "4", "--max-sessions", "8",
                   "--session-isolation", "--network", "allow", "--ingress", "host-loopback",
                   "--capability-cache", "none", "--state-dir", str(root / "state")]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        owned = []
        try:
            sidecar = BoundedSidecar(process)
            deadline = time.monotonic() + 300
            sidecar.ok({"id":1,"op":"probe","waitMs":60000},deadline)
            for i, name in enumerate(("a","b"), 2):
                sidecar.ok({"id":i,"op":"session.open","session":name,"workspace":str(root/name),
                            "memoryMiB":memory},deadline)
            owned = vmm_processes(process.pid)
            quota = (memory - 96) // 2 // 8
            report = {}
            scripts = {"storage": STORAGE.replace("EXPECTED",str(quota))}
            if memory >= 4096:
                scripts["workloads"] = WORKLOAD
            for i, (name, script) in enumerate(scripts.items(), 10):
                sidecar.ok({"id":i,"op":"exec","session":"a","execId":name,
                            "argv":["python3","-c",script]},deadline)
                sidecar.succeeded([name],deadline)
                report[name] = json.loads(sidecar.stdout_of(name))
            if memory >= 4096:
                (root/"a"/"node-check.cjs").write_text(NODE_WORKLOAD, encoding="utf-8")
                sidecar.ok({"id":20,"op":"exec","session":"a","execId":"node",
                            "argv":["node","/workspace/node-check.cjs"]},deadline)
                sidecar.succeeded(["node"],deadline)
                report["node"] = json.loads(sidecar.stdout_of("node"))
            sidecar.ok({"id":30,"op":"exec","session":"b","execId":"isolation",
                        "argv":["python3","-c",
                                "import os;assert not os.path.exists('/home/session/private-marker');"
                                "assert not os.path.exists('/workspace/test.docx');print('isolated')"]},deadline)
            sidecar.succeeded(["isolation"],deadline)
            diagnostic = sidecar.ok({"id":31,"op":"diagnostics"},deadline)
            assert diagnostic["vm"]["sessionStorageMiB"] == quota, diagnostic
            report["memoryMiB"] = memory
            report["isolated"] = True
            output.mkdir(parents=True, exist_ok=True)
            for path in (root/"a").iterdir():
                if path.is_file(): shutil.copyfile(path,output/path.name)
            for i,name in enumerate(("a","b"),40):
                sidecar.ok({"id":i,"op":"session.close","session":name},deadline)
            (output/f"result-{memory}.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
            print(json.dumps(report),flush=True)
        finally:
            stop_sidecar(process)
            for handle in owned:
                try: handle.wait()
                finally: handle.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--nvxd",type=Path,required=True)
    parser.add_argument("--repo",type=Path,required=True)
    parser.add_argument("--initrd",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--memory",type=int,nargs="+",choices=(512,4096),default=(512,4096))
    args=parser.parse_args()
    for memory in args.memory:
        run(args,memory,args.output)


if __name__=="__main__":
    main()
