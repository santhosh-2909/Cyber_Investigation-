import re
import random

def get_hex():
    return "".join(random.choices("0123456789ABCDEF", k=32))

with open('templates/landing.html', 'r') as f:
    content = f.read()

# Replace binary rain spans with hex strings
content = re.sub(r'>[01]{32}<', lambda m: f">{get_hex()}<", content)

# Enhance binary rain CSS
# Change colors to neon green/cyan
css_rain_old = ".binary-rain-full span{display:block;width:14px;color:#9e4bff;font:800 20px/1.42 var(--font-mono,monospace);text-align:center;text-shadow:0 0 10px #6c2bff"
css_rain_new = ".binary-rain-full span{display:block;width:14px;color:#00ff41;font:800 20px/1.42 var(--font-mono,monospace);text-align:center;text-shadow:0 0 10px #008f11"
content = content.replace(css_rain_old, css_rain_new)

css_rain_old2 = ".binary-rain-full span:nth-child(2n){color:#5530a8"
css_rain_new2 = ".binary-rain-full span:nth-child(2n){color:#008f11"
content = content.replace(css_rain_old2, css_rain_new2)

css_rain_old3 = ".binary-rain-full span:nth-child(3n){color:#db7cff;text-shadow:0 0 18px #bd39ff"
css_rain_new3 = ".binary-rain-full span:nth-child(3n){color:#38edbc;text-shadow:0 0 18px #00ffbc"
content = content.replace(css_rain_old3, css_rain_new3)

# Enhance Ring (.neural-wrap)
# Change purple gradients and borders to neon cyan/green
content = content.replace("border:1px solid rgba(70,234,255,.46)", "border:2px solid rgba(0,255,188,.6)")
content = content.replace("rgba(155,77,255,.4),rgba(35,12,72,.16)", "rgba(0,255,65,.4),rgba(0,30,10,.2)")
content = content.replace("box-shadow:inset 0 0 40px rgba(86,50,255,.32),0 0 46px rgba(71,223,255,.17)", "box-shadow:inset 0 0 50px rgba(0,255,65,.4),0 0 60px rgba(0,255,188,.3)")
content = content.replace("border:1px solid rgba(191,93,255,.58)", "border:1px solid rgba(56,237,188,.7)")

# Orbits
content = content.replace("border-color:rgba(63,233,247,.72)", "border-color:rgba(0,255,65,.8)")
content = content.replace("border-color:rgba(196,102,255,.6)", "border-color:rgba(0,255,188,.7)")

# Nodes
content = content.replace("background:#42e7f8;box-shadow:0 0 18px 6px rgba(65,231,247,.56)", "background:#00ff41;box-shadow:0 0 20px 8px rgba(0,255,65,.7)")
content = content.replace("background:#bd58ff;", "background:#00ffbc;")

# Neural links
content = content.replace("background:linear-gradient(90deg,transparent,#49eafa,#c05cff,transparent)", "background:linear-gradient(90deg,transparent,#00ff41,#00ffbc,transparent)")
content = content.replace("box-shadow:0 0 12px #6beeff", "box-shadow:0 0 15px #00ff41")

# Enhance Case File (.case-visual)
content = content.replace("border:1px solid rgba(192,92,255,.72)", "border:1px solid rgba(0,255,188,.8)")
content = content.replace("linear-gradient(145deg,rgba(35,15,68,.95),rgba(6,6,21,.9) 58%,rgba(15,45,68,.8))", "linear-gradient(145deg,rgba(0,40,20,.95),rgba(4,10,6,.9) 58%,rgba(0,40,30,.8))")
content = content.replace("box-shadow:inset 0 0 32px rgba(142,55,255,.22),0 0 28px rgba(137,48,255,.36)", "box-shadow:inset 0 0 40px rgba(0,255,188,.3),0 0 35px rgba(0,255,65,.4)")
content = content.replace("border:1px solid rgba(64,227,247,.24)", "border:1px solid rgba(0,255,188,.4)")
content = content.replace("linear-gradient(#8d3cff,#1a0c35)", "linear-gradient(#00ffbc,#001a11)")
content = content.replace("background:#9b4dff;color:#fff;font:800 9px var(--font-mono,monospace);letter-spacing:.14em;box-shadow:0 0 14px #8d39e8", "background:#00ff41;color:#000;font:800 9px var(--font-mono,monospace);letter-spacing:.14em;box-shadow:0 0 16px #00ff41")

with open('templates/landing.html', 'w') as f:
    f.write(content)

print("Updated landing.html with cyber themes!")
