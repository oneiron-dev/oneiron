/* An element's role and accessible name: the words a screen reader says
   for it. A working subset of the W3C name computation (accname 1.2), in
   this order: aria-labelledby, aria-label, a field's <label>, the text of
   an element whose role takes its name from its content, title; a text
   field with none of these falls back to its placeholder.

   It reads attributes, child nodes, text, getElementById and a field's
   labels only, so a test can run it on a hand-built stand-in tree. */

/* Roles whose name may come from the element's own text. */
const NAME_FROM_CONTENT = new Set([
  'button',
  'cell',
  'checkbox',
  'columnheader',
  'gridcell',
  'heading',
  'link',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'option',
  'radio',
  'rowheader',
  'switch',
  'tab',
  'tooltip',
  'treeitem',
])

/* Input types a person types text into. */
const TEXT_INPUT_TYPES = new Set(['', 'text', 'email', 'search', 'url', 'tel', 'password', 'number'])

const ELEMENT_NODE = 1
const TEXT_NODE = 3

function tagName(el: Element): string {
  return (el.tagName || '').toUpperCase()
}

function readAttribute(el: Element, name: string): string | null {
  return typeof el.getAttribute === 'function' ? el.getAttribute(name) : null
}

function inputType(el: Element): string {
  return (readAttribute(el, 'type') ?? '').toLowerCase()
}

function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

/* A field a person types into: a text input, a text area, a textbox role
   or an editable element. */
export function isTextField(el: Element): boolean {
  const tag = tagName(el)
  if (tag === 'TEXTAREA') return true
  if (tag === 'INPUT') return TEXT_INPUT_TYPES.has(inputType(el))
  return readAttribute(el, 'role') === 'textbox' || readAttribute(el, 'contenteditable') === 'true'
}

/* The element's role: the first token of its role attribute, else the role
   its tag carries. Empty for an element with no role worth naming. */
export function accessibleRole(el: Element): string {
  const declared = readAttribute(el, 'role')?.trim().split(/\s+/)[0]
  if (declared) return declared
  switch (tagName(el)) {
    case 'BUTTON':
    case 'SUMMARY':
      return 'button'
    case 'A':
      return readAttribute(el, 'href') !== null ? 'link' : ''
    case 'TEXTAREA':
      return 'textbox'
    case 'SELECT':
      return readAttribute(el, 'multiple') !== null ? 'listbox' : 'combobox'
    case 'OPTION':
      return 'option'
    case 'NAV':
      return 'navigation'
    case 'ASIDE':
      return 'complementary'
    case 'DIALOG':
      return 'dialog'
    case 'MAIN':
      return 'main'
    case 'FORM':
      return 'form'
    case 'SECTION':
      return 'region'
    case 'INPUT': {
      const type = inputType(el)
      if (type === 'checkbox' || type === 'radio') return type
      if (type === 'button' || type === 'submit' || type === 'reset' || type === 'image') return 'button'
      if (type === 'range') return 'slider'
      if (type === 'search') return 'searchbox'
      return TEXT_INPUT_TYPES.has(type) ? 'textbox' : ''
    }
    default:
      return readAttribute(el, 'contenteditable') === 'true' ? 'textbox' : ''
  }
}

/* Parts a screen reader passes over: hidden from assistive technology or
   not drawn, scripts and styles, and layers (a tooltip, a popover), which
   are not the text of the element they sit in. */
function passedOver(el: Element): boolean {
  if (readAttribute(el, 'aria-hidden') === 'true' || readAttribute(el, 'hidden') !== null) return true
  const tag = tagName(el)
  if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEMPLATE') return true
  return readAttribute(el, 'popover') !== null || readAttribute(el, 'role') === 'tooltip'
}

/* The text an element gives from its content: its text nodes, the alt of a
   picture, the label of a labelled child, the value of an embedded field. */
function textOfContent(el: Element): string {
  const out: string[] = []
  const nodes = el.childNodes ?? []
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]
    if (node.nodeType === TEXT_NODE) {
      out.push(node.nodeValue ?? '')
      continue
    }
    if (node.nodeType !== ELEMENT_NODE) continue
    const child = node as Element
    if (passedOver(child)) continue
    const label = readAttribute(child, 'aria-label')
    if (label && label.trim()) out.push(` ${label} `)
    else if (tagName(child) === 'IMG') out.push(` ${readAttribute(child, 'alt') ?? ''} `)
    else if (tagName(child) === 'INPUT' || tagName(child) === 'TEXTAREA') out.push(` ${(child as HTMLInputElement).value ?? ''} `)
    else out.push(` ${textOfContent(child)} `)
  }
  return out.join('')
}

/* The words of the elements an aria-labelledby lists, each by its own
   aria-label or else its content. */
function textOfLabelledBy(el: Element, ids: string): string {
  const doc = el.ownerDocument
  if (!doc || typeof doc.getElementById !== 'function') return ''
  return ids
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => {
      const ref = doc.getElementById(id)
      if (!ref) return ''
      const label = readAttribute(ref, 'aria-label')
      return label && label.trim() ? label : textOfContent(ref)
    })
    .join(' ')
}

/* The text of a field's <label> elements, or of the label it sits in. */
function textOfFieldLabels(el: Element): string {
  const labels = (el as HTMLInputElement).labels
  if (labels && labels.length) {
    const out: string[] = []
    for (let i = 0; i < labels.length; i++) out.push(textOfContent(labels[i]))
    return out.join(' ')
  }
  for (let up = el.parentElement; up; up = up.parentElement) {
    if (tagName(up) === 'LABEL') return textOfContent(up)
  }
  return ''
}

/* The accessible name of an element; empty when it has none. */
export function accessibleName(el: Element): string {
  const ids = readAttribute(el, 'aria-labelledby')
  if (ids && ids.trim()) {
    const named = collapse(textOfLabelledBy(el, ids))
    if (named) return named
  }
  const label = collapse(readAttribute(el, 'aria-label') ?? '')
  if (label) return label
  const tag = tagName(el)
  const field = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'
  if (field) {
    const fromLabels = collapse(textOfFieldLabels(el))
    if (fromLabels) return fromLabels
  } else if (NAME_FROM_CONTENT.has(accessibleRole(el))) {
    const fromContent = collapse(textOfContent(el))
    if (fromContent) return fromContent
  }
  const title = collapse(readAttribute(el, 'title') ?? '')
  if (title) return title
  if (isTextField(el)) return collapse(readAttribute(el, 'placeholder') ?? readAttribute(el, 'aria-placeholder') ?? '')
  return ''
}
