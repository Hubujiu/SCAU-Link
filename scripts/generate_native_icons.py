"""Optional asset regeneration. Building the native app uses the generated header."""
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from fontTools.pens.recordingPen import RecordingPen
from fontTools.svgLib import SVGPath

root = Path(__file__).resolve().parents[1]
source = (root / 'ui/prototype/assets/icons.js').read_text(encoding='utf-8')
icons = json.loads(source[source.index('{'):source.rindex('}') + 1])
names = {
    'Sprout': 'sprout', 'Network': 'network', 'User': 'user-round',
    'Ethernet': 'ethernet-port', 'List': 'list', 'Settings': 'settings-2',
    'Shield': 'shield-check', 'Clock': 'clock-3', 'Refresh': 'refresh-cw',
    'Logout': 'log-out', 'ArrowRight': 'arrow-right', 'ArrowLeft': 'arrow-left',
    'ChevronDown': 'chevron-down', 'ChevronRight': 'chevron-right',
    'Eye': 'eye', 'EyeOff': 'eye-off', 'Minimize': 'minus', 'Maximize': 'square',
    'Close': 'x', 'Check': 'check', 'Alert': 'circle-alert',
    'Monitor': 'monitor', 'Moon': 'moon', 'Power': 'power',
    'Key': 'lock-keyhole', 'Panel': 'panel-top', 'File': 'file-text',
    'Plus': 'plus', 'Star': 'star', 'Grip': 'grip-vertical', 'Trash': 'trash-2',
    'Restore': 'copy', 'Pin': 'arrow-up-to-line', 'AppMark': 'app-mark', 'Search': 'search',
    'Wifi': 'wifi', 'ExternalLink': 'external-link',
}
out = [
    '// UI icons: Lucide 0.468.0, ISC license. AppMark: assets/app-icon.svg, GPL-3.0.',
    '// See third_party/lucide/LICENSE. Do not hand-edit the path data.',
    '#pragma once', '#include <span>',
    'namespace scau::desktop::visual {',
    'enum class Icon { None, ' + ', '.join(names) + ' };',
    'struct PathOp { char type; float x1=0, y1=0, x2=0, y2=0, x3=0, y3=0; };',
]

def number(x):
    text = f'{x:.5f}'.rstrip('0').rstrip('.')
    return text + ('.f' if '.' not in text else 'f')

for name, key in names.items():
    pen = RecordingPen()
    if key == 'app-mark':
        logo = ET.parse(root/'assets/app-icon.svg').getroot()
        group = next(e for e in logo.iter() if e.attrib.get('id') == 'mark')
        group.attrib.pop('transform', None)
        svg = ET.Element('{http://www.w3.org/2000/svg}svg')
        svg.append(group)
        data = ET.tostring(svg)
    elif key in icons:
        data = icons[key]
    else:
        data = (root/'assets/lucide'/f'{key}.svg').read_text(encoding='utf-8')
    SVGPath.fromstring(data).draw(pen)
    out.append(f'inline constexpr PathOp path_{name}[] = {{')
    for command, points in pen.value:
        op = {'moveTo': 'M', 'lineTo': 'L', 'curveTo': 'C',
              'qCurveTo': 'Q', 'closePath': 'Z', 'endPath': 'E'}[command]
        values = [v for point in points for v in point]
        out.append("    {'" + op + "'" + ''.join(', ' + number(v) for v in values) + '},')
    out.append('};')
out.append('inline std::span<const PathOp> icon_path(Icon icon) { switch(icon) {')
for name in names:
    out.append(f'case Icon::{name}: return path_{name};')
out.extend(['default: return {};', '}}', '} // namespace scau::desktop::visual', ''])
(root/'src/desktop/icons.hpp').write_text('\n'.join(out), encoding='utf-8')
license_dir = root/'third_party/lucide'
license_dir.mkdir(exist_ok=True)
(license_dir/'LICENSE').write_bytes((root/'ui/prototype/assets/LUCIDE-LICENSE').read_bytes())
print(f'Generated {len(names)} native vector icons.')
