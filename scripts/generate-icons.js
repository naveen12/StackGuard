import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

const svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="none">
  <rect width="512" height="512" rx="128" fill="#090D16"/>
  <rect x="16" y="16" width="480" height="480" rx="112" stroke="#38BDF8" stroke-opacity="0.35" stroke-width="8"/>
  <path d="M256 72L120 136V248C120 338.4 178 418.8 256 440C334 418.8 392 338.4 392 248V136L256 72Z" fill="#111827" stroke="#38BDF8" stroke-width="20" stroke-linejoin="round"/>
  <path d="M256 120L152 168V248C152 318 196.4 380 256 397C315.6 380 360 318 360 248V168L256 120Z" fill="#0F172A" stroke="#38BDF8" stroke-width="12" opacity="0.8"/>
  <circle cx="256" cy="240" r="32" fill="#38BDF8"/>
  <path d="M256 272V320" stroke="#38BDF8" stroke-width="24" stroke-linecap="round"/>
</svg>`;

const foregroundSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="none">
  <path d="M256 72L120 136V248C120 338.4 178 418.8 256 440C334 418.8 392 338.4 392 248V136L256 72Z" fill="#111827" stroke="#38BDF8" stroke-width="20" stroke-linejoin="round"/>
  <path d="M256 120L152 168V248C152 318 196.4 380 256 397C315.6 380 360 318 360 248V168L256 120Z" fill="#0F172A" stroke="#38BDF8" stroke-width="12" opacity="0.8"/>
  <circle cx="256" cy="240" r="32" fill="#38BDF8"/>
  <path d="M256 272V320" stroke="#38BDF8" stroke-width="24" stroke-linecap="round"/>
</svg>`;

const densities = [
  { folder: 'mipmap-mdpi', size: 48, fgSize: 108 },
  { folder: 'mipmap-hdpi', size: 72, fgSize: 162 },
  { folder: 'mipmap-xhdpi', size: 96, fgSize: 216 },
  { folder: 'mipmap-xxhdpi', size: 144, fgSize: 324 },
  { folder: 'mipmap-xxxhdpi', size: 192, fgSize: 432 },
];

const resDir = path.resolve(process.cwd(), 'android/app/src/main/res');

async function generate() {
  const svgBuffer = Buffer.from(svgContent);
  const fgBuffer = Buffer.from(foregroundSvg);

  for (const d of densities) {
    const targetDir = path.join(resDir, d.folder);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    // Generate ic_launcher.png
    await sharp(svgBuffer)
      .resize(d.size, d.size)
      .toFile(path.join(targetDir, 'ic_launcher.png'));

    // Generate ic_launcher_round.png
    await sharp(svgBuffer)
      .resize(d.size, d.size)
      .toFile(path.join(targetDir, 'ic_launcher_round.png'));

    // Generate ic_launcher_foreground.png
    await sharp(fgBuffer)
      .resize(d.fgSize, d.fgSize)
      .toFile(path.join(targetDir, 'ic_launcher_foreground.png'));

    console.log(`Generated launcher icons for ${d.folder}`);
  }
}

generate().catch((err) => {
  console.error(err);
  process.exit(1);
});
