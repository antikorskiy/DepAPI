from .sd import *
def init():
    global config,style,features,H,S,V,Style
    config = ensure_config_file(None)
    style = toml.loads(default_toml).get('style', {})
    features = toml.loads(default_toml).get('features')
    H, S, V = style.get("HSV")

    for color in ["Dark", "Mid", "Symbol", "Head", "Grey", "Bright"]:
        setattr(Style, color, apply_multipliers(style, color, H, S, V))
    for attr in ['PrettyPad', 'PrettyBroken', 'Margin', 'ListIndent', 'Syntax']:
        setattr(Style, attr, style.get(attr))
    for attr in ['Links', 'Images', 'CodeSpaces', 'Clipboard', 'Logging', 'Timeout', 'Savebrace']:
        setattr(state, attr, features.get(attr))

    Style.MarginSpaces = " " * Style.Margin
    state.WidthArg = style.get("Width") or 0
    Style.Blockquote = f"{FG}{Style.Grey}│ "
    width_calc()
    Style.Codebg = f"{BG}{Style.Dark}"
    Style.Link = f"{FG}{Style.Symbol}{UNDERLINE[0]}"
