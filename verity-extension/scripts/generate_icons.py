import os
from PIL import Image, ImageDraw

colors = {
    'safe': '#0E9F6E',
    'caution': '#F59E0B',
    'danger': '#DC2626'
}

sizes = [16, 32, 48, 128]
out_dir = r"e:\Finebehaviour\verity-extension\icons"

os.makedirs(out_dir, exist_ok=True)

for state, color in colors.items():
    for size in sizes:
        img = Image.new('RGBA', (size, size), (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw circle
        margin = size * 0.05
        draw.ellipse([margin, margin, size - margin, size - margin], fill=color)
        
        if state == 'safe':
            # Draw checkmark
            points = [
                (size*0.3, size*0.5),
                (size*0.45, size*0.65),
                (size*0.7, size*0.35)
            ]
            draw.line(points, fill="white", width=max(2, int(size*0.08)), joint="curve")
        else:
            # Draw exclamation mark
            w = max(2, int(size*0.1))
            draw.line([(size*0.5, size*0.25), (size*0.5, size*0.6)], fill="white", width=w)
            draw.ellipse([size*0.5 - w/2, size*0.7, size*0.5 + w/2, size*0.7 + w], fill="white")
            
        img.save(os.path.join(out_dir, f"{state}_{size}.png"))

print("Icons generated successfully.")
