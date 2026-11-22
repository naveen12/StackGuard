import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="none">
  <rect width="512" height="512" rx="128" fill="#090D16"/>
  <rect x="16" y="16" width="480" height="480" rx="112" stroke="#38BDF8" stroke-opacity="0.35" stroke-width="8"/>
  <path d="M256 72L120 136V248C120 338.4 178 418.8 256 440C334 418.8 392 338.4 392 248V136L256 72Z" fill="#111827" stroke="#38BDF8" stroke-width="20" stroke-linejoin="round"/>
  <path d="M256 120L152 168V248C152 318 196.4 380 256 397C315.6 380 360 318 360 248V168L256 120Z" fill="#0F172A" stroke="#38BDF8" stroke-width="12" opacity="0.8"/>
  <circle cx="256" cy="240" r="32" fill="#38BDF8"/>
  <path d="M256 272V320" stroke="#38BDF8" stroke-width="24" stroke-linecap="round"/>
</svg>`;

const artifactDir = `C:/Users/navee/AppData/Local/Google/AndroidStudio2026.2.2/projects/stackguard.6a38ee11/.artifacts/9689bc61-9f91-410d-8a06-cecad4d0955d`;

if (!fs.existsSync(artifactDir)) {
  fs.mkdirSync(artifactDir, { recursive: true });
}

const targetPath = path.join(artifactDir, 'stackguard-app-icon.png');

sharp(Buffer.from(svg))
  .resize(512, 512)
  .toFile(targetPath)
  .then(() => console.log('Successfully saved app icon PNG to artifact directory:', targetPath))
  .catch((err) => console.error(err));
