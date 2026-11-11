import * as React from 'react'

/* Joins class names, skipping empty values. */
export function cx(...names: Array<string | false | null | undefined>): string {
  return names.filter(Boolean).join(' ')
}

/* A layout effect on the client, a plain effect on the server (no layout
   exists there). */
export const useIsomorphicLayoutEffect = typeof window === 'undefined' ? React.useEffect : React.useLayoutEffect

/* One callback ref that writes every given ref. */
export function mergeRefs<T>(...refs: Array<React.Ref<T> | undefined>): React.RefCallback<T> {
  return (node: T | null) => {
    const cleanups: Array<() => void> = []
    for (const ref of refs) {
      if (typeof ref === 'function') {
        const cleanup = ref(node)
        if (typeof cleanup === 'function') cleanups.push(cleanup)
      } else if (ref) {
        ;(ref as React.RefObject<T | null>).current = node
      }
    }
    if (cleanups.length) return () => cleanups.forEach((c) => c())
    return undefined
  }
}

/* State that a parent may own (value + onChange) or leave to the component
   (defaultValue). The setter reports every change either way. */
export function useControllableState<T>(
  controlled: T | undefined,
  defaultValue: T,
  onChange: ((next: T) => void) | undefined,
): [T, (next: T) => void] {
  const [inner, setInner] = React.useState(defaultValue)
  const isControlled = controlled !== undefined
  const value = isControlled ? controlled : inner
  const onChangeRef = React.useRef(onChange)
  const valueRef = React.useRef(value)
  useIsomorphicLayoutEffect(() => {
    onChangeRef.current = onChange
    valueRef.current = value
  })
  const set = React.useCallback(
    (next: T) => {
      if (!isControlled) setInner(next)
      if (!Object.is(next, valueRef.current)) {
        valueRef.current = next
        onChangeRef.current?.(next)
      }
    },
    [isControlled],
  )
  return [value, set]
}

type AnyProps = Record<string, unknown>

/* Merges the slot's props into its single child: handlers chain (the
   child's first; the slot's is skipped when the child prevents default),
   class names join, styles merge, refs both receive the node. */
export function mergeSlotProps(slot: AnyProps, child: AnyProps): AnyProps {
  const out: AnyProps = { ...slot, ...child }
  for (const key of Object.keys(slot)) {
    const s = slot[key]
    const c = child[key]
    if (/^on[A-Z]/.test(key) && typeof s === 'function' && typeof c === 'function') {
      out[key] = (event: unknown, ...rest: unknown[]) => {
        ;(c as (...a: unknown[]) => void)(event, ...rest)
        const prevented = !!(event && typeof event === 'object' && (event as { defaultPrevented?: boolean }).defaultPrevented)
        if (!prevented) (s as (...a: unknown[]) => void)(event, ...rest)
      }
    } else if (key === 'className') {
      out[key] = cx(s as string, c as string)
    } else if (key === 'style') {
      out[key] = { ...(s as object), ...(c as object) }
    } else if (key === 'ref') {
      out[key] = mergeRefs(s as React.Ref<unknown>, c as React.Ref<unknown>)
    }
  }
  return out
}

/* Renders its single child element with the slot's props merged in. */
export function Slot({ children, ...slotProps }: AnyProps & { children?: React.ReactNode }) {
  if (!React.isValidElement(children)) return null
  const child = children as React.ReactElement<AnyProps>
  return React.cloneElement(child, mergeSlotProps(slotProps, child.props))
}

/* An id that is safe inside url(#…) references and CSS selectors. */
export function useSafeId(prefix: string): string {
  return `${prefix}-${React.useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
}
