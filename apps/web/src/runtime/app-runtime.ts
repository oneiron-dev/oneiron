/** The application host is not an engine connection or a vault identity. */
export type AppSurface = 'web' | 'desktop'

export type AppRuntime = Readonly<{
  surface: AppSurface
  dataSource: 'fixtures'
  engine: Readonly<{ status: 'not-configured' }>
}>

/**
 * Both entry points use the same fixture UI. No discovery, transport, native
 * command or task lifecycle is started here. Future engine integration belongs
 * at this router-context boundary, not in the desktop window lifecycle.
 */
export function createFixtureRuntime(surface: AppSurface): AppRuntime {
  return Object.freeze({
    surface,
    dataSource: 'fixtures',
    engine: Object.freeze({ status: 'not-configured' as const }),
  })
}

export type AppRouterContext = { runtime: AppRuntime }
