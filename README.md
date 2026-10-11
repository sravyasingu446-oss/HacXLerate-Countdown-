# HacXLerate 2026 Countdown

A single-page countdown timer for the 24-hour HacXLerate 2026 hackathon. The page is self-contained: HTML, CSS, JavaScript, and logo images are all included in `index.html`.

## Features

- 24-hour countdown with elapsed-time display and progress bar
- Start and reset controls
- Countdown state saved in browser local storage, so it continues after a reload
- Fullscreen toggle
- Responsive layout designed to fit within one screen without page scrolling

## Run

Open `index.html` in a modern web browser. No installation, build step, or dependencies are required.

Alternatively, serve the file locally from its directory:

```powershell
python -m http.server 8000
```

Then open <http://localhost:8000>.

## Use

Select **Start 24h** to begin the countdown. Select **Reset** to clear it. The **Fullscreen** button toggles fullscreen mode. The timer state is stored in the current browser's local storage.
