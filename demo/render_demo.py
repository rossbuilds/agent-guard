"""Render a terminal-style demo of agent-guard to demo/demo.mp4 (+ demo.gif)."""
import json, os, subprocess, shutil, tempfile
from PIL import Image, ImageDraw, ImageFont
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
W, H, FPS = 1280, 720, 15
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 24)
BIG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 30)
BG, FG, GRN, RED, YEL, DIM, CYA = (24,26,33),(220,220,220),(80,220,120),(255,90,90),(250,200,80),(130,130,140),(100,200,255)
def guard(cmd):
    inp = json.dumps({"tool_name":"Bash","tool_input":{"command":cmd},"cwd":ROOT})
    out = subprocess.run(["python3", os.path.join(ROOT,"agent_guard.py")], input=inp, capture_output=True, text=True).stdout.strip()
    return json.loads(out)["hookSpecificOutput"] if out else None
lines, frames = [], []
def frame(n=1):
    img = Image.new("RGB",(W,H),BG); d = ImageDraw.Draw(img)
    d.rectangle([0,0,W,40],fill=(40,42,52))
    for i,c in enumerate([(255,95,86),(255,189,46),(39,201,63)]): d.ellipse([16+i*26,12,32+i*26,28],fill=c)
    d.text((W//2-150,8),"claude code  +  agent-guard",font=FONT,fill=DIM)
    y=60
    for text,col,f in lines[-17:]: d.text((30,y),text,font=f or FONT,fill=col); y+=38
    frames.extend([img]*n)
def say(text,col=FG,f=None,hold=8): lines.append((text,col,f)); frame(hold)
def type_(prefix,text,col=FG):
    lines.append((prefix,col,None))
    steps = list(range(0, len(text) + 1, 2))
    if steps[-1] != len(text):
        steps.append(len(text))
    for i in steps:
        lines[-1] = (prefix + text[:i], col, None)
        frame(1)
    frame(6)
def run(cmd):
    type_("● Bash($ ", cmd+")", CYA)
    r = guard(cmd)
    if not r: say("  ✓ allowed — runs normally", GRN, hold=14); return
    if r["permissionDecision"]=="deny": say("  ✗ BLOCKED  "+r["permissionDecisionReason"], RED, hold=22)
    else: say("  ? ASK      "+r["permissionDecisionReason"], YEL, hold=14); say("    → you must confirm before it runs", YEL, hold=14)
say("agent-guard: stop your AI agent from nuking things", FG, BIG, 18)
say("> clean up the repo and redeploy", DIM, hold=14)
run("ls -la && npm test")
run("rm -rf ~")
run("git push --force origin main")
run('psql -c "DROP DATABASE prod"')
run("terraform destroy -auto-approve")
say("", hold=1); say("One line install:", FG, BIG, 6)
say("curl -fsSL https://raw.githubusercontent.com/rossbuilds/", GRN, hold=2); say("     agent-guard/v0.1.0/install.sh | bash", GRN, hold=45)
tmp = tempfile.mkdtemp()
for i,f in enumerate(frames): f.save(f"{tmp}/{i:05d}.png")
subprocess.run(["ffmpeg","-y","-loglevel","error","-framerate",str(FPS),"-i",f"{tmp}/%05d.png","-c:v","libx264","-pix_fmt","yuv420p",os.path.join(HERE,"demo.mp4")],check=True)
subprocess.run(["ffmpeg","-y","-loglevel","error","-i",os.path.join(HERE,"demo.mp4"),"-vf","fps=10,scale=960:-1:flags=lanczos","-loop","0",os.path.join(HERE,"demo.gif")],check=True)
shutil.rmtree(tmp); print(len(frames)/FPS,"s")
