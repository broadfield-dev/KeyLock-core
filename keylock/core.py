# keylock/core.py
import io
import json
import os
import struct
import logging
import traceback
import base64
import random

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

from PIL import Image, ImageDraw, ImageFont
import numpy as np

logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SALT_SIZE = 16; NONCE_SIZE = 12; TAG_SIZE = 16; KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000; LENGTH_HEADER_SIZE = 4
PREFERRED_FONTS = ["Verdana", "Arial", "DejaVu Sans", "Calibri", "Helvetica", "Roboto-Regular", "sans-serif"]
MAX_KEYS_TO_DISPLAY_OVERLAY = 12

def _get_font(preferred_fonts, base_size):
    fp = None
    safe_base_size = int(base_size)
    if safe_base_size <= 0:
        safe_base_size = 10
    for n in preferred_fonts:
        try: ImageFont.truetype(n.lower()+".ttf",10); fp=n.lower()+".ttf"; break
        except IOError:
            try: ImageFont.truetype(n,10); fp=n; break
            except IOError: continue
    if fp:
        try: return ImageFont.truetype(fp, safe_base_size)
        except IOError: logger.warning(f"Font '{fp}' load failed with size {safe_base_size}. Defaulting.")
    try:
        return ImageFont.load_default(size=safe_base_size)
    except TypeError:
        return ImageFont.load_default()

def set_pil_image_format_to_png(image:Image.Image)->Image.Image:
    buf=io.BytesIO(); image.save(buf,format='PNG'); buf.seek(0)
    reloaded=Image.open(buf); reloaded.format="PNG"; return reloaded

def _derive_key(pw:str,salt:bytes)->bytes:
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=KEY_SIZE,salt=salt,iterations=PBKDF2_ITERATIONS)
    return kdf.derive(pw.encode('utf-8'))

def encrypt_data(data:bytes,pw:str)->bytes:
    s=os.urandom(SALT_SIZE);k=_derive_key(pw,s);a=AESGCM(k);n=os.urandom(NONCE_SIZE)
    ct=a.encrypt(n,data,None); return s+n+ct

def decrypt_data(payload:bytes,pw:str)->bytes:
    ml=SALT_SIZE+NONCE_SIZE+TAG_SIZE;
    if len(payload)<ml: raise ValueError("Payload too short.")
    s,n,ct_tag=payload[:SALT_SIZE],payload[SALT_SIZE:SALT_SIZE+NONCE_SIZE],payload[SALT_SIZE+NONCE_SIZE:]
    k=_derive_key(pw,s);a=AESGCM(k)
    try: return a.decrypt(n,ct_tag,None)
    except InvalidTag: raise ValueError("Decryption failed: Invalid password/corrupted data.")
    except Exception as e: logger.error(f"Decrypt error: {e}",exc_info=True); raise

def _d2b(d:bytes)->str: return ''.join(format(b,'08b') for b in d)
def _b2B(b:str)->bytes:
    if len(b)%8!=0: raise ValueError("Bits not multiple of 8.")
    return bytes(int(b[i:i+8],2) for i in range(0,len(b),8))

def embed_data_in_image(img_obj:Image.Image,data:bytes)->Image.Image:
    img=img_obj.convert("RGB");px=np.array(img);fpx=px.ravel()
    lb=struct.pack('>I',len(data));fp=lb+data;db=_d2b(fp);nb=len(db)
    if nb>len(fpx): raise ValueError(f"Data too large: {nb} bits needed, {len(fpx)} available.")
    for i in range(nb): fpx[i]=(fpx[i]&0xFE)|int(db[i])
    spx=fpx.reshape(px.shape); return Image.fromarray(spx.astype(np.uint8),'RGB')

def extract_data_from_image(img_obj:Image.Image)->bytes:
    img=img_obj.convert("RGB");px=np.array(img);fpx=px.ravel()
    hbc=LENGTH_HEADER_SIZE*8
    if len(fpx)<hbc: raise ValueError("Image too small for header.")
    lb="".join(str(fpx[i]&1) for i in range(hbc))
    try: pl=struct.unpack('>I',_b2B(lb))[0]
    except Exception as e: raise ValueError(f"Header decode error: {e}")
    if pl==0: return b""
    if pl>(len(fpx)-hbc)/8: raise ValueError("Header len corrupted or > capacity.")
    tpb=pl*8; so=hbc; eo=so+tpb
    if len(fpx)<eo: raise ValueError("Image truncated or header corrupted.")
    pb="".join(str(fpx[i]&1) for i in range(so,eo)); return _b2B(pb)

def parse_kv_string_to_dict(kv_str:str)->dict:
    if not kv_str or not kv_str.strip(): return {}
    dd={};
    for ln,ol in enumerate(kv_str.splitlines(),1):
        l=ol.strip()
        if not l or l.startswith('#'): continue
        lc=l.split('#',1)[0].strip();
        if not lc: continue
        p=lc.split('=',1) if '=' in lc else lc.split(':',1) if ':' in lc else []
        if len(p)!=2: raise ValueError(f"L{ln}: Invalid format '{ol}'.")
        k,v=p[0].strip(),p[1].strip()
        if not k: raise ValueError(f"L{ln}: Empty key in '{ol}'.")
        if len(v)>=2 and v[0]==v[-1] and v.startswith(("'",'"')): v=v[1:-1]
        dd[k]=v
    return dd

def _generate_starfield_image(w=800, h=800) -> Image.Image:
    """Generates a visually appealing starfield image."""
    if w <= 0 or h <= 0:
        return Image.new("RGB", (w, h), (0, 0, 5))

    center_x, center_y = w / 2, h / 2
    y_coords, x_coords = np.mgrid[0:h, 0:w]
    distance = np.sqrt((x_coords - center_x)**2 + (y_coords - center_y)**2)
    max_distance = np.sqrt(center_x**2 + center_y**2)
    distance_norm = distance / max_distance if max_distance > 0 else np.zeros_like(distance)

    bg_center_color = np.array([20, 25, 40])
    bg_outer_color = np.array([0, 0, 5])
    gradient = bg_outer_color + (bg_center_color - bg_outer_color) * (1 - distance_norm[..., np.newaxis])
    img = Image.fromarray(gradient.astype(np.uint8), 'RGB')
    draw = ImageDraw.Draw(img)

    # Tiny stars (dust)
    for _ in range(int((w * h) / 200)):
        x, y = random.randint(0, w - 1), random.randint(0, h - 1)
        brightness = random.randint(30, 90)
        draw.point((x, y), fill=(int(brightness*0.9), int(brightness*0.9), brightness))

    # Brighter, glowing stars
    star_colors = [(255, 255, 255), (220, 230, 255), (255, 240, 220)]
    for _ in range(int((w * h) / 1000)):
        x, y = random.randint(0, w - 1), random.randint(0, h - 1)
        size = 0.5 + (2.5 * (random.random() ** 2))
        brightness = 120 + (135 * (random.random() ** 1.5))
        color = random.choice(star_colors)
        final_color = tuple(int(c * (brightness / 255.0)) for c in color)
        glow_size = size * 3
        glow_color = tuple(int(c * 0.3) for c in final_color)
        draw.ellipse([x - glow_size, y - glow_size, x + glow_size, y + glow_size], fill=glow_color)
        draw.ellipse([x - size, y - size, x + size, y + size], fill=final_color)
    return img

def generate_keylock_carrier_image(base_image: Image.Image = None, w: int = 800, h: int = 600) -> Image.Image:
    """
    Creates a carrier image for steganography, preserving the original function name.
    
    If a `base_image` (PIL.Image.Image) is provided, it returns a copy of it.
    If no `base_image` is provided, it generates a new starfield image of size (w, h).
    The 'msg' parameter from the original function is no longer used.
    """
    if base_image:
        logger.info("Using provided base image.")
        return base_image.copy()
    else:
        logger.info(f"No base image provided, generating a {w}x{h} starfield image.")
        return _generate_starfield_image(w, h)

def _get_text_measurement(draw_obj, text_str, font_obj):
    """Returns (width, height) of text using the best available Pillow method."""
    if hasattr(draw_obj, 'textbbox'):
        try:
            bbox = draw_obj.textbbox((0, 0), text_str, font=font_obj)
            width = bbox[2] - bbox[0]
            height = bbox[3] - bbox[1]
            return width, height
        except Exception: pass
    try:
        if hasattr(font_obj, 'getsize'): return font_obj.getsize(text_str)
        return draw_obj.textsize(text_str, font=font_obj)
    except AttributeError:
        try:
            char_width_approx = font_obj.size * 0.6
            char_height_approx = font_obj.size
            return int(len(text_str) * char_width_approx), int(char_height_approx)
        except: return len(text_str) * 8, 10

def draw_key_list_dropdown_overlay(image: Image.Image, keys: list[str] = None, title: str = "Data Embedded") -> Image.Image:
    """Draws an overlay with a title and list of keys, styled to match the starfield theme."""
    if not title and (keys is None or not keys):
        return set_pil_image_format_to_png(image.copy())

    img_overlayed = image.copy().convert("RGBA")
    draw = ImageDraw.Draw(img_overlayed, "RGBA")

    # --- Style and Color Palette (Starfield Theme) ---
    margin = 15; padding = {'title_x':12,'title_y':8,'key_x':12,'key_y':6}; line_spacing = 5
    title_bg_color = (10, 15, 30, 220)      # Dark blue, semi-transparent
    title_text_color = (200, 220, 255)     # Light blue/white
    key_list_bg_color = (15, 20, 35, 200) # Slightly lighter dark blue
    key_text_color = (190, 200, 230)      # Off-white
    ellipsis_color = (150, 160, 180)      # Greyish blue

    # --- Overlay Sizing and Font Logic (from original robust implementation) ---
    OVERLAY_TARGET_WIDTH_RATIO = 0.35; MIN_OVERLAY_WIDTH_PX = 200; MAX_OVERLAY_WIDTH_PX = 600
    final_overlay_box_width = min(max(int(image.width*OVERLAY_TARGET_WIDTH_RATIO),MIN_OVERLAY_WIDTH_PX),MAX_OVERLAY_WIDTH_PX)
    final_overlay_box_width = min(final_overlay_box_width, image.width - 2 * margin)

    TITLE_FONT_SIZE = min(max(min(int(image.height*0.03),int(final_overlay_box_width*0.08)),14),28)
    KEY_FONT_SIZE = min(max(min(int(image.height*0.025),int(final_overlay_box_width*0.07)),12),22)
    title_font = _get_font(PREFERRED_FONTS, TITLE_FONT_SIZE)
    key_font = _get_font(PREFERRED_FONTS, KEY_FONT_SIZE)

    # --- Text Dimension Calculation ---
    actual_title_w, actual_title_h = _get_text_measurement(draw, title, title_font)
    disp_keys, actual_key_text_widths, total_keys_render_h, key_line_heights = [],[],0,[]
    if keys:
        temp_disp_keys=keys[:MAX_KEYS_TO_DISPLAY_OVERLAY-1]+[f"... ({len(keys)-(MAX_KEYS_TO_DISPLAY_OVERLAY-1)} more)"] if len(keys)>MAX_KEYS_TO_DISPLAY_OVERLAY else keys
        for kt in temp_disp_keys:
            disp_keys.append(kt); kw, kh = _get_text_measurement(draw, kt, key_font)
            actual_key_text_widths.append(kw); key_line_heights.append(kh)
            total_keys_render_h += kh
        if len(disp_keys)>1: total_keys_render_h += line_spacing*(len(disp_keys)-1)

    # --- Drawing: Title Bar (Top-Right) ---
    title_bar_h = actual_title_h + 2 * padding['title_y']
    title_bar_x1 = image.width - margin; title_bar_x0 = title_bar_x1 - final_overlay_box_width
    title_bar_y0 = margin; title_bar_y1 = title_bar_y0 + title_bar_h
    draw.rectangle([(title_bar_x0, title_bar_y0), (title_bar_x1, title_bar_y1)], fill=title_bg_color)
    available_w = final_overlay_box_width - 2 * padding['title_x']
    title_text_draw_x = title_bar_x0 + padding['title_x'] + max(0, (available_w - actual_title_w) / 2)
    draw.text((title_text_draw_x, title_bar_y0 + padding['title_y']), title, font=title_font, fill=title_text_color)

    # --- Drawing: Key List ---
    if disp_keys:
        key_list_box_h = total_keys_render_h + 2*padding['key_y']
        key_list_x0, key_list_x1 = title_bar_x0, title_bar_x1
        key_list_y0 = title_bar_y1
        key_list_y1 = min(key_list_y0 + key_list_box_h, image.height - margin)
        draw.rectangle([(key_list_x0,key_list_y0),(key_list_x1,key_list_y1)],fill=key_list_bg_color)

        current_text_y = key_list_y0 + padding['key_y']
        available_text_width_for_keys = final_overlay_box_width - 2 * padding['key_x']
        for i, key_text_item in enumerate(disp_keys):
            if i >= len(key_line_heights) or current_text_y + key_line_heights[i] > key_list_y1 - padding['key_y']:
                _, ellipsis_h = _get_text_measurement(draw,"...",key_font)
                if current_text_y + ellipsis_h <= key_list_y1 - padding['key_y']:
                    ellipsis_w, _ = _get_text_measurement(draw,"...",key_font)
                    draw.text((key_list_x0 + (final_overlay_box_width - ellipsis_w)/2, current_text_y), "...", font=key_font, fill=ellipsis_color)
                break

            text_to_draw = key_text_item
            if actual_key_text_widths[i] > available_text_width_for_keys:
                temp_text = key_text_item
                while _get_text_measurement(draw, temp_text + "...", key_font)[0] > available_text_width_for_keys and len(temp_text) > 0:
                    temp_text = temp_text[:-1]
                text_to_draw = temp_text + "..." if len(temp_text) < len(key_text_item) else temp_text

            final_key_text_w, _ = _get_text_measurement(draw, text_to_draw, key_font)
            key_text_draw_x = key_list_x0 + padding['key_x'] + max(0, (available_text_width_for_keys - final_key_text_w) / 2)
            is_ellipsis = "..." in text_to_draw or "more)" in key_text_item
            draw.text((key_text_draw_x, current_text_y), text_to_draw, font=key_font, fill=ellipsis_color if is_ellipsis else key_text_color)
            current_text_y += key_line_heights[i] + line_spacing

    # --- Finalize Image ---
    final_image_rgb = Image.new("RGB", img_overlayed.size, (0, 0, 0))
    final_image_rgb.paste(img_overlayed, (0, 0), img_overlayed)
    return set_pil_image_format_to_png(final_image_rgb)
