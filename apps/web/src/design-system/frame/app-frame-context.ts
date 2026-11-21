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

/* What an item of the microsidebar needs from the frame so its place's
   sidebar shows over the sheet while the sidebar is folded (the peek). */
export interface MicroSidebarPeek {
  /* This item's sidebar shows over the work area now: hide its tooltip. */
  peeking: boolean
  /* Spread on the item's box, the element that holds the control. */
  itemProps: {
    'data-micro-sidebar-id'?: string
    onPointerEnter?: (event: React.PointerEvent<HTMLElement>) => void
    onPointerLeave?: (event: React.PointerEvent<HTMLElement>) => void
    onPointerDown?: (event: React.PointerEvent<HTMLElement>) => void
  }
  /* Call from the control's key handler: with the sidebar folded,
     ArrowRight opens the peek with focus inside it. */
  onControlKeyDown: (event: React.KeyboardEvent<HTMLElement>) => void
}

/* Lets a caller build a microsidebar item of its own (a vault switch, a
   companion's face) that previews its place as MicroSidebar.Item does.
   Outside an AppFrame, or without an id, it does nothing. */
export function useMicroSidebarPeek(id: string | undefined): MicroSidebarPeek {
  const frame = React.useContext(AppFrameContext)
  return React.useMemo<MicroSidebarPeek>(() => {
    if (!frame || !id) return { peeking: false, itemProps: { 'data-micro-sidebar-id': id }, onControlKeyDown: () => {} }
    return {
      peeking: frame.peekId === id,
      itemProps: {
        'data-micro-sidebar-id': id,
        onPointerEnter: (event) => frame.itemPointerEnter(id, event),
        onPointerLeave: (event) => frame.itemPointerLeave(id, event),
        onPointerDown: (event) => frame.itemPointerDown(id, event),
      },
      onControlKeyDown: (event) => {
        if (!event.defaultPrevented) frame.itemKeyDown(id, event)
      },
    }
  }, [frame, id])
}
