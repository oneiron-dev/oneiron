import * as React from 'react'

/* What an AppFrame tells the parts inside it: whether its sidebar shows,
   which microsidebar item's sidebar is peeking, and the handlers a
   microsidebar item reports its pointer and keys to. */
export interface AppFrameContextValue {
  /* The sidebar column is on screen. */
  sidebarShown: boolean
  /* The current place has a sidebar at all. */
  hasSidebar: boolean
  setSidebarOpen: (open: boolean) => void
  /* The item whose sidebar shows over the work area. */
  peekId: string | null
  itemPointerEnter: (id: string, event: React.PointerEvent<HTMLElement>) => void
  itemPointerLeave: (id: string, event: React.PointerEvent<HTMLElement>) => void
  itemPointerDown: (id: string, event: React.PointerEvent<HTMLElement>) => void
  itemKeyDown: (id: string, event: React.KeyboardEvent<HTMLElement>) => void
}

export const AppFrameContext = React.createContext<AppFrameContextValue | null>(null)

/* True inside the peek: the sidebar raised over the sheet while it is
   folded. The fold control there keeps the sidebar open. */
export const AppFramePeekContext = React.createContext(false)
