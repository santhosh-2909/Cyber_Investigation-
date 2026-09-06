import re

with open('templates/landing.html', 'r') as f:
    content = f.read()

# Replace HTML
old_html = """  <div class="binary-rain rain-top-left" aria-hidden="true"><span style="--d:-1s">0100110100101101</span><span style="--d:-4s">1101001010100110</span><span style="--d:-2s">0011010111010010</span><span style="--d:-5s">1010100100110110</span></div>
  <div class="binary-rain rain-bottom-right" aria-hidden="true"><span style="--d:-3s">0100110100101101</span><span style="--d:-6s">1101001010100110</span><span style="--d:-1s">0011010111010010</span><span style="--d:-4s">1010100100110110</span></div>"""

new_html = """  <div class="binary-rain-full" aria-hidden="true">
    <span style="--d:-1s">01001101001011011101001010100110</span>
    <span style="--d:-4s">11010010101001100100110100101101</span>
    <span style="--d:-2s">00110101110100101010100100110110</span>
    <span style="--d:-5s">10101001001101100011010111010010</span>
    <span style="--d:-3s">01001101001011011101001010100110</span>
    <span style="--d:-6s">11010010101001100100110100101101</span>
    <span style="--d:-1s">00110101110100101010100100110110</span>
    <span style="--d:-4s">10101001001101100011010111010010</span>
    <span style="--d:-7s">01001101001011011101001010100110</span>
    <span style="--d:-2s">11010010101001100100110100101101</span>
    <span style="--d:-8s">00110101110100101010100100110110</span>
    <span style="--d:-3s">10101001001101100011010111010010</span>
    <span style="--d:-5s">01001101001011011101001010100110</span>
    <span style="--d:-9s">11010010101001100100110100101101</span>
    <span style="--d:-2s">00110101110100101010100100110110</span>
    <span style="--d:-6s">10101001001101100011010111010010</span>
    <span style="--d:-1s">01001101001011011101001010100110</span>
    <span style="--d:-4s">11010010101001100100110100101101</span>
    <span style="--d:-7s">00110101110100101010100100110110</span>
    <span style="--d:-3s">10101001001101100011010111010010</span>
  </div>"""

content = content.replace(old_html, new_html)

# Replace CSS
css_old = ".binary-rain{position:absolute;z-index:1;pointer-events:none;display:flex;gap:21px;opacity:.75}.binary-rain span{display:block;width:14px;color:#9e4bff;font:800 20px/1.42 var(--font-mono,monospace);text-align:center;text-shadow:0 0 10px #6c2bff;animation:rain-drop 6s linear infinite;animation-delay:var(--d);filter:blur(.1px)}.binary-rain span:nth-child(2n){color:#5530a8;font-size:16px}.binary-rain span:nth-child(3n){color:#db7cff;text-shadow:0 0 18px #bd39ff}.rain-top-left{left:5%;top:-150px;height:430px;mask-image:linear-gradient(transparent,black 23%,black 70%,transparent);-webkit-mask-image:linear-gradient(transparent,black 23%,black 70%,transparent)}.rain-bottom-right{right:5%;bottom:-180px;height:420px;transform:rotate(2deg);mask-image:linear-gradient(transparent,black 23%,black 70%,transparent);-webkit-mask-image:linear-gradient(transparent,black 23%,black 70%,transparent)}.rain-bottom-right span{animation-direction:reverse;animation-duration:7s}"

css_new = ".binary-rain-full{position:absolute;inset:0;z-index:1;pointer-events:none;display:flex;justify-content:space-evenly;opacity:.35;overflow:hidden;mask-image:linear-gradient(transparent,black 10%,black 90%,transparent);-webkit-mask-image:linear-gradient(transparent,black 10%,black 90%,transparent)}.binary-rain-full span{display:block;width:14px;color:#9e4bff;font:800 20px/1.42 var(--font-mono,monospace);text-align:center;text-shadow:0 0 10px #6c2bff;animation:rain-drop-full 10s linear infinite;animation-delay:var(--d);filter:blur(.1px);word-break:break-all}.binary-rain-full span:nth-child(2n){color:#5530a8;font-size:16px;animation-direction:reverse;animation-duration:14s}.binary-rain-full span:nth-child(3n){color:#db7cff;text-shadow:0 0 18px #bd39ff;animation-duration:8s}.binary-rain-full span:nth-child(4n){animation-direction:reverse;animation-duration:12s}"

content = content.replace(css_old, css_new)

# Replace keyframes
kf_old = "@keyframes rain-drop{from{transform:translateY(-105px)}to{transform:translateY(255px)}}"
kf_new = "@keyframes rain-drop-full{from{transform:translateY(-100vh)}to{transform:translateY(100vh)}}"

content = content.replace(kf_old, kf_new)

with open('templates/landing.html', 'w') as f:
    f.write(content)
print("Replaced!")
