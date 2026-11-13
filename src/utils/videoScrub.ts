export const SCRUB_SENSITIVITY = 1.15;
export const TOTAL_ROBOT_FRAMES = 97;
export const SHEET_COLS = 3;
export const SHEET_ROWS = 3;
export const FRAMES_PER_SHEET = SHEET_COLS * SHEET_ROWS;
export const SHEET_COUNT = Math.ceil(TOTAL_ROBOT_FRAMES / FRAMES_PER_SHEET);
export const TILE_WIDTH = 1280;
export const TILE_HEIGHT = 724;

export function computeScrubTime(
  currentTargetTime: number,
  deltaX: number,
  viewportWidth: number,
  duration: number,
  sensitivity: number = SCRUB_SENSITIVITY,
): number {
  if (!Number.isFinite(duration) || duration <= 0 || viewportWidth <= 0) {
    return 0;
  }
  const offset = (deltaX / viewportWidth) * sensitivity * duration;
  const next = currentTargetTime + offset;
  return Math.max(0, Math.min(duration, next));
}

export function computeScrubFrame(
  currentTargetFrame: number,
  deltaX: number,
  viewportWidth: number,
  totalFrames: number = TOTAL_ROBOT_FRAMES,
  sensitivity: number = SCRUB_SENSITIVITY,
): number {
  if (!Number.isFinite(totalFrames) || totalFrames <= 1 || viewportWidth <= 0) {
    return 0;
  }
  const maxIndex = totalFrames - 1;
  const offset = (deltaX / viewportWidth) * sensitivity * maxIndex;
  const next = currentTargetFrame + offset;
  return Math.max(0, Math.min(maxIndex, next));
}

export function stepSmoothValue(
  current: number,
  target: number,
  dtSeconds: number,
  speed: number = 14,
): number {
  if (Math.abs(target - current) < 1e-4) {
    return target;
  }
  const clampedDt = Math.max(0, Math.min(0.1, dtSeconds));
  const factor = 1 - Math.exp(-speed * clampedDt);
  return current + (target - current) * factor;
}

export interface CoverCropRect {
  sx: number;
  sy: number;
  sw: number;
  sh: number;
}

export function computeCoverCropRect(
  destWidth: number,
  destHeight: number,
  srcWidth: number,
  srcHeight: number,
  focalXRatio: number = 0.5,
  focalYRatio: number = 0.5,
): CoverCropRect {
  if (destWidth <= 0 || destHeight <= 0 || srcWidth <= 0 || srcHeight <= 0) {
    return { sx: 0, sy: 0, sw: srcWidth, sh: srcHeight };
  }

  const destAspect = destWidth / destHeight;
  const srcAspect = srcWidth / srcHeight;

  if (srcAspect > destAspect) {
    // Source is wider than destination: crop horizontally according to focalXRatio
    const sw = srcHeight * destAspect;
    const maxOffset = Math.max(0, srcWidth - sw);
    const sx = maxOffset * Math.max(0, Math.min(1, focalXRatio));
    return { sx, sy: 0, sw, sh: srcHeight };
  }

  // Source is taller than destination: crop vertically according to focalYRatio
  const sh = srcWidth / destAspect;
  const maxOffset = Math.max(0, srcHeight - sh);
  const sy = maxOffset * Math.max(0, Math.min(1, focalYRatio));
  return { sx: 0, sy, sw: srcWidth, sh };
}
