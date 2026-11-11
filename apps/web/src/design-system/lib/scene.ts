import { loadImage } from './field-art'
import { themeSeedFromPixels, toneMapFromPixels, type ThemeSeed, type ToneMap } from './theme'

/* Reading a scene's picture in the browser: its seed, its tone map, and
   the tone map as a grey picture ready to be drawn cover-fit. Each picture
   is read once per page; the root and the window ground share the result. */

/* The picture is reduced to this width before it is read: plenty for a
   ground printed in 2 px cells, and quick to read. */
const SCENE_SAMPLE_WIDTH = 480

export interface SceneReading {
  seed: ThemeSeed
  toneMap: ToneMap
  /* The tone map as a grey canvas (one pixel per value). */
  tonePicture: HTMLCanvasElement
}

const readings = new Map<string, Promise<SceneReading>>()

function readPicture(img: HTMLImageElement): SceneReading {
  const width = SCENE_SAMPLE_WIDTH
  const height = Math.max(1, Math.round((img.naturalHeight * width) / Math.max(1, img.naturalWidth)))
  const sample = document.createElement('canvas')
  sample.width = width
  sample.height = height
  const ctx = sample.getContext('2d', { willReadFrequently: true })
  if (!ctx) throw new Error('no 2d canvas to read the scene')
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.drawImage(img, 0, 0, width, height)
  const pixels = ctx.getImageData(0, 0, width, height)
  const toneMap = toneMapFromPixels(pixels)
  const grey = ctx.createImageData(width, height)
  for (let i = 0; i < toneMap.values.length; i++) {
    const v = Math.round(toneMap.values[i] * 255)
    const p = i * 4
    grey.data[p] = v
    grey.data[p + 1] = v
    grey.data[p + 2] = v
    grey.data[p + 3] = 255
  }
  const tonePicture = document.createElement('canvas')
  tonePicture.width = width
  tonePicture.height = height
  tonePicture.getContext('2d')?.putImageData(grey, 0, 0)
  return { seed: themeSeedFromPixels(pixels), toneMap, tonePicture }
}

/* The reading of the picture at `url`, cached for the page's lifetime. A
   picture that fails to load is not cached, so a later call tries again. */
export function readScene(url: string): Promise<SceneReading> {
  let pending = readings.get(url)
  if (!pending) {
    pending = loadImage(url).then(readPicture)
    pending.catch(() => readings.delete(url))
    readings.set(url, pending)
  }
  return pending
}
