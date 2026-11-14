import * as React from 'react'
import { cx, mergeRefs, Slot, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { endAfterScroll, followScrollEnd, readScrollBox, type ScrollBox } from './place-scroll'

export interface PlaceProps extends React.ComponentPropsWithRef<'div'> {
  /* Render the single child element (a Tabs root, for a room with views)
     as the place. */
  asChild?: boolean
}

/* One place in the work area: Place.Head, Place.Body, Place.Foot, in a
   column that fills its parent. The column keeps to the left edge, so a
   pane opening at the right never moves it. */
function PlaceRoot({ asChild = false, className, children, ...props }: PlaceProps) {
  if (asChild) {
    return (
      <Slot className={cx('sl-place', className)} {...props}>
        {children}
      </Slot>
    )
  }
  return (
    <div className={cx('sl-place', className)} {...props}>
      {children}
    </div>
  )
}

export interface PlaceHeadSlotProps extends React.ComponentPropsWithRef<'div'> {}

/* The head line: a PlaceHead, or a RoomHead. */
function PlaceHeadSlot({ className, ...props }: PlaceHeadSlotProps) {
  return <div className={cx('sl-place-head-slot', className)} {...props} />
}

export interface PlaceBodyProps extends React.ComponentPropsWithRef<'div'> {}

/* The scrolling body. Its content ends at the bottom; it opens at the end,
   and while the person is at the end, content added there (or a foot
   that grows, or a column that widens) keeps the end in view. Once the
   person has scrolled up, it keeps their position. Only the person's
   scrolls decide whether they are at the end (see endAfterScroll). */
function PlaceBody({ ref, className, children, onScroll, ...props }: PlaceBodyProps) {
  const bodyRef = React.useRef<HTMLDivElement | null>(null)
  const contentRef = React.useRef<HTMLDivElement | null>(null)
  const atEnd = React.useRef(true)
  /* The geometry the body last read or set. */
  const measured = React.useRef<ScrollBox | null>(null)
  const followRef = React.useRef<() => void>(() => {})

  useIsomorphicLayoutEffect(() => {
    const body = bodyRef.current
    const content = contentRef.current
    if (!body || !content) return
    const follow = () => {
      const top = followScrollEnd(atEnd.current, body)
      if (top !== null && Math.abs(body.scrollTop - top) > 0.5) body.scrollTop = top
      measured.current = readScrollBox(body)
    }
    followRef.current = follow
    follow()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(follow)
    observer.observe(content)
    observer.observe(body)
    return () => observer.disconnect()
  }, [])

  return (
    <div
      ref={mergeRefs(ref, bodyRef)}
      className={cx('sl-place-body', className)}
      onScroll={(event) => {
        onScroll?.(event)
        const body = event.currentTarget
        atEnd.current = endAfterScroll(atEnd.current, body, measured.current)
        measured.current = readScrollBox(body)
        if (atEnd.current) followRef.current()
      }}
      {...props}
    >
      <div ref={contentRef} className="sl-place-content">
        {children}
      </div>
    </div>
  )
}

export interface PlaceFootProps extends React.ComponentPropsWithRef<'div'> {}

/* The foot, outside the scroll: the write box. */
function PlaceFoot({ className, ...props }: PlaceFootProps) {
  return <div className={cx('sl-place-foot', className)} {...props} />
}

/* Compound parts: Place, .Head, .Body, .Foot. */
export const Place = Object.assign(PlaceRoot, { Head: PlaceHeadSlot, Body: PlaceBody, Foot: PlaceFoot })
