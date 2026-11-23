# Dorkbrain Autoindex Theme - v2

_A clean, portable, zero‑backend theme for nginx autoindex with icon font support._

## **Overview**

Dorkbrain Autoindex Theme is a fully static, drop‑in enhancement for nginx's built‑in `autoindex` module. It transforms the default directory listing into a polished, dark‑themed file explorer with:

- **Icon font support** (Material Design Icons, Font Awesome, Bootstrap Icons)
- grid‑aligned columns
- full‑row hover effects
- smooth fade‑in
- portable stylesheet + favicon resolution
- zero CGI, zero SSI, zero backend logic
- graceful fallback if JS fails

Everything lives inside a `.autoindex/` directory and can be deployed anywhere in your file tree.

## **Features**

- **Icon fonts** — Choose from Material Design Icons (MDI), Font Awesome, or Bootstrap Icons
- **Smart file type detection** — Icons automatically match file extensions (archives, images, videos, code, documents, etc.)
- **Dark theme** inspired by CardFlask + GitHub Dark
- **Grid‑based table layout** (no `<pre>` alignment issues)
- **Directory/file color distinction**
- **Portable CSS + favicon resolution**
- **Smooth fade‑in** to eliminate FOUC
- **Minimal external dependencies** — Optional CDN icon fonts only
- **Works at any directory depth**

## **Quick Start**

### **1. Extract the theme**

Place the `.autoindex/` directory at the root of your served directory:
```
/files/
    .autoindex/
        style.css
        head.html
        foot.html
        favicon.svg   (optional)
```

### **2. Enable autoindex in nginx**

Inside your server block:
```nginx
location /files/ {
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    add_before_body /files/.autoindex/head.html;
    add_after_body  /files/.autoindex/foot.html;
}
```

### **3. Configure icon fonts (Optional)**

At the top of `head.html`, set your preferred icon font:
```js
const AI_FONT_THEME = "mdi";  // Options: "mdi", "fa", "bs", or "" (disabled)
```

**Icon font options:**
- `"mdi"` — Material Design Icons
- `"fa"` — Font Awesome (free icons)
- `"bs"` — Bootstrap Icons
- `""` — Disabled (no icons)

### **4. (Optional) Add your own favicon**

Drop any file into `.autoindex/` and set the filename at the top of `head.html`:
```js
const AI_FAVICON = "favicon.svg";
```

### **5. Reload nginx**

```
sudo nginx -s reload
```

- Navigate to `/files/` and enjoy the themed autoindex.

## **Directory Structure**

```
.autoindex/
│
├── style.css        # Main theme stylesheet
├── head.html        # Injected before autoindex output
├── foot.html        # Injected after autoindex output
└── favicon.svg      # User-defined favicon (optional)
```

## **How It Works**

- nginx renders its normal autoindex HTML
- `head.html` loads the theme, optional icon font CDN, and JS
- JS rewrites paths to `.autoindex/style.css` and favicon (works at any depth)
- JS parses the `<pre>` listing and replaces it with a grid table
- Icons are automatically assigned based on file extensions
- The page fades in once fully themed

If JS fails, the user sees the native autoindex output (graceful degradation).

## **Supported File Types**

Icons automatically detect and display for:
- **Archives:** zip, rar, 7z, tar, gz, bz2, xz
- **Images:** jpg, png, gif, svg, webp, ico
- **Videos:** mp4, avi, mkv, mov, webm
- **Audio:** mp3, wav, flac, ogg, m4a
- **Code:** js, py, java, c, cpp, php, html, css, json, sh
- **Documents:** pdf, doc, docx, txt, md
- **Spreadsheets:** xls, xlsx, csv

## **Compatibility**

- nginx autoindex (any modern version)
- Works at any directory depth
- Optional CDN dependencies (icon fonts)
- No server‑side logic
