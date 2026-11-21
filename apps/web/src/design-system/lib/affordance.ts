import { accessibleName, accessibleRole, isTextField } from './accessible-name'

/* Declared verbs. In the app a person's press and an agent's call run the
   same named verb, so a control that runs one says so in the DOM:
   `data-verb` (dotted, `vault.rooms.members.remove`), `data-verb-params`
   (JSON of plain values) and `data-verb-gate`, what an agent acting for
   the person may do with it: `auto` it runs, `proposed` it waits for the
   person's yes, `person` only the person runs it.

   affordance() gives the attributes for the element a person operates.
   readAffordances() lists every declared control under a root, in
   document order, with its accessible name, role, state and the named
   regions around it. findAffordance() finds one by verb and params. */

export type AffordanceGate = 'auto' | 'proposed' | 'person'

export const AFFORDANCE_GATES: readonly AffordanceGate[] = ['auto', 'proposed', 'person']

/* Ids and plain values only. */
export type AffordanceParams = Record<string, string | number | boolean | null>

export interface AffordanceSpec {
  verb: string
  params?: AffordanceParams
  /* `auto` when left out. */
  gate?: AffordanceGate
}

/* The attributes to spread on the element a person operates. */
export interface AffordanceAttributes {
  'data-verb': string
  'data-verb-params'?: string
  'data-verb-gate': AffordanceGate
}

/* What the control shows, where it applies. */
export interface AffordanceState {
  /* A text field's text, or the option a select shows. */
  value?: string
  /* A checkbox, a radio, or a toggle button's pressed state. */
  checked?: boolean | 'mixed'
  selected?: boolean
  expanded?: boolean
  disabled?: true
  /* The control marks the current place: `page`, `true`. */
  current?: string
}

export interface Affordance {
  ref: Element
  /* Empty when the control has no accessible name, which is a fault of
     the screen, not of the list. */
  name: string
  role: string
  state: AffordanceState
  verb: string
  params: AffordanceParams
  gate: AffordanceGate
  /* The names of the named regions around it, outermost first. */
  region: string[]
}

export function affordance({ verb, params, gate = 'auto' }: AffordanceSpec): AffordanceAttributes {
  const attributes: AffordanceAttributes = { 'data-verb': verb, 'data-verb-gate': gate }
  if (params && Object.keys(params).length) attributes['data-verb-params'] = JSON.stringify(params)
  return attributes
}

/* The params in an attribute; empty when it is missing, not JSON, or not
   an object. Values that are not plain are left out. */
export function parseVerbParams(json: string | null | undefined): AffordanceParams {
  if (!json) return {}
  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    return {}
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const params: AffordanceParams = {}
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') params[key] = v
  }
  return params
}

/* A gate from an attribute; anything unknown reads as `auto`. */
export function gateOf(value: string | null | undefined): AffordanceGate {
  return (AFFORDANCE_GATES as readonly string[]).includes(value ?? '') ? (value as AffordanceGate) : 'auto'
}

/* Every key of `wanted` is in `params` with the same value. */
export function paramsContain(params: AffordanceParams, wanted: AffordanceParams = {}): boolean {
  return Object.entries(wanted).every(([key, value]) => Object.is(params[key], value))
}

/* Roles that name a region around a control, when they carry a name. */
const REGION_ROLES = new Set(['alertdialog', 'complementary', 'dialog', 'group', 'menu', 'navigation', 'radiogroup', 'region', 'tablist'])

function readAttribute(el: Element, name: string): string | null {
  return typeof el.getAttribute === 'function' ? el.getAttribute(name) : null
}

function hasAttribute(el: Element, name: string): boolean {
  return readAttribute(el, name) !== null
}

/* A subtree nothing is listed from: marked for no agent, hidden from
   assistive technology, inert or hidden. */
function leftOut(el: Element): boolean {
  return hasAttribute(el, 'data-agent-hidden') || readAttribute(el, 'aria-hidden') === 'true' || hasAttribute(el, 'inert') || hasAttribute(el, 'hidden')
}

/* Drawn on screen: not inside a closed layer, not display none, not
   visibility hidden. Only a browser can tell; elsewhere it counts as
   drawn. */
function onScreen(el: Element): boolean {
  const check = (el as Element & { checkVisibility?: (options?: { visibilityProperty?: boolean }) => boolean }).checkVisibility
  return typeof check === 'function' ? check.call(el, { visibilityProperty: true }) : true
}

function readBoolean(value: string | null): boolean | undefined {
  if (value === 'true') return true
  if (value === 'false') return false
  return undefined
}

/* The state a control shows. `secret`: its value is left out (a password
   field is always secret). */
export function affordanceState(el: Element, secret: boolean): AffordanceState {
  const state: AffordanceState = {}
  const tag = (el.tagName || '').toUpperCase()
  const type = (readAttribute(el, 'type') ?? '').toLowerCase()
  if (!secret && !(tag === 'INPUT' && type === 'password')) {
    if (tag === 'SELECT') {
      const option = (el as HTMLSelectElement).selectedOptions?.[0]
      state.value = option ? (option.textContent ?? '').trim() : ((el as HTMLSelectElement).value ?? '')
    } else if (tag === 'INPUT' || tag === 'TEXTAREA') {
      if (isTextField(el)) state.value = (el as HTMLInputElement).value ?? ''
    } else if (isTextField(el)) {
      state.value = (el.textContent ?? '').trim()
    }
  }
  const checked = readAttribute(el, 'aria-checked')
  const pressed = readAttribute(el, 'aria-pressed')
  if (checked === 'mixed' || pressed === 'mixed') state.checked = 'mixed'
  else if (readBoolean(checked) !== undefined) state.checked = readBoolean(checked)
  else if (readBoolean(pressed) !== undefined) state.checked = readBoolean(pressed)
  else if (tag === 'INPUT' && (type === 'checkbox' || type === 'radio')) state.checked = !!(el as HTMLInputElement).checked
  const selected = readBoolean(readAttribute(el, 'aria-selected'))
  if (selected !== undefined) state.selected = selected
  const expanded = readBoolean(readAttribute(el, 'aria-expanded'))
  if (expanded !== undefined) state.expanded = expanded
  if (hasAttribute(el, 'disabled') || readAttribute(el, 'aria-disabled') === 'true') state.disabled = true
  const current = readAttribute(el, 'aria-current')
  if (current && current !== 'false') state.current = current
  return state
}

/* The names of the named regions around a control, outermost first. */
export function affordanceRegion(el: Element): string[] {
  const names: string[] = []
  for (let up = el.parentElement; up; up = up.parentElement) {
    if (!REGION_ROLES.has(accessibleRole(up))) continue
    const name = accessibleName(up)
    if (name) names.unshift(name)
  }
  return names
}

/* Every element under `root`, and `root` itself, that declares a verb, in
   document order. `data-agent-hidden` on an element leaves its subtree
   out; `data-agent-secret` keeps its controls listed without their
   values. */
export function readAffordances(root: Element | Document | null | undefined): Affordance[] {
  const found: Affordance[] = []
  if (!root) return found
  const start = (root as Document).documentElement ?? (root as Element)
  let secret = false
  for (let up = start.parentElement; up; up = up.parentElement) {
    if (leftOut(up)) return found
    if (hasAttribute(up, 'data-agent-secret')) secret = true
  }
  const visit = (el: Element, inSecret: boolean) => {
    if (leftOut(el)) return
    const isSecret = inSecret || hasAttribute(el, 'data-agent-secret')
    const verb = readAttribute(el, 'data-verb')
    if (verb && onScreen(el)) {
      found.push({
        ref: el,
        name: accessibleName(el),
        role: accessibleRole(el),
        state: affordanceState(el, isSecret),
        verb,
        params: parseVerbParams(readAttribute(el, 'data-verb-params')),
        gate: gateOf(readAttribute(el, 'data-verb-gate')),
        region: affordanceRegion(el),
      })
    }
    const children = el.children
    if (!children) return
    for (let i = 0; i < children.length; i++) visit(children[i], isSecret)
  }
  visit(start, secret)
  return found
}

/* The first control under `root` that declares `verb` with params that
   contain `params`. */
export function findAffordance(
  root: Element | Document | null | undefined,
  { verb, params }: { verb: string; params?: AffordanceParams },
): Affordance | null {
  return readAffordances(root).find((a) => a.verb === verb && paramsContain(a.params, params)) ?? null
}
