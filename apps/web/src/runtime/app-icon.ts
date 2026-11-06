import { invoke } from '@tauri-apps/api/core'

export type AppIconAppearance = 'light' | 'system' | 'dark'

/** A supported native host, not the UI theme or the desktop build target. */
export function supportsAppIconAppearance(windowChrome: string | undefined, native: boolean): boolean {
  return native && windowChrome === 'macos'
}

export function readAppIconAppearance(): Promise<AppIconAppearance> {
  return invoke('get_app_icon_appearance')
}

export function writeAppIconAppearance(preference: AppIconAppearance): Promise<AppIconAppearance> {
  return invoke('set_app_icon_appearance', { preference })
}
