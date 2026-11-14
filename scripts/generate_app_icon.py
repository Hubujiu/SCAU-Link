"""Optional regeneration of Windows icon resources from the SVG master."""
from pathlib import Path
import io
from PIL import Image
from resvg_py import svg_to_bytes

root=Path(__file__).resolve().parents[1]
master=(root/'assets/app-icon.svg').read_text(encoding='utf-8')
variants={'app':master,'offline':master.replace('#3B9171','#94A299').replace('#195F49','#65796C'),
          'connecting':master.replace('#3B9171','#C9AA64').replace('#195F49','#927237')}
for name,svg in variants.items():
    png=svg_to_bytes(svg_string=svg,width=256,height=256)
    if name=='app':(root/'assets/app-icon.png').write_bytes(png)
    image=Image.open(io.BytesIO(png)).convert('RGBA')
    image.save(root/'assets'/f'{name}.ico',format='ICO',sizes=[(n,n) for n in [16,20,24,32,40,48,64,128,256]])
print('Generated native application/tray ICO resources and preview from app-icon.svg.')
