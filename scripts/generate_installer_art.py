"""Render installer branding from the project's existing vector icon."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from resvg_py import svg_to_bytes
import io

root = Path(__file__).resolve().parents[1]
svg = (root / 'assets/app-icon.svg').read_text(encoding='utf-8')
icon = Image.open(io.BytesIO(svg_to_bytes(svg_string=svg, width=192, height=192))).convert('RGBA')
side = Image.new('RGB', (384, 720), '#edf4ec')
draw = ImageDraw.Draw(side)
for y in range(720):
    t = y / 719
    rgb = tuple(round(a + (b-a)*t) for a,b in zip((238,245,236),(222,236,224)))
    draw.line((0,y,384,y), fill=rgb)
side.paste(icon, (52, 110), icon)
font = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 40)
small = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 22)
draw.text((52, 332), 'SCAU', fill='#214f40', font=font)
draw.text((52, 382), 'Link', fill='#214f40', font=font)
draw.line((52, 560, 270, 560), fill='#b8d2be', width=2)
draw.text((52, 590), 'Windows x64', fill='#6c8977', font=small)
side.save(root / 'assets/setup-sidebar.bmp')
small_icon = Image.new('RGB', (96,96), 'white')
icon = icon.resize((80,80), Image.Resampling.LANCZOS)
small_icon.paste(icon, (8,8), icon)
small_icon.save(root / 'assets/setup-logo.bmp')
print('Generated native installer branding from assets/app-icon.svg')
