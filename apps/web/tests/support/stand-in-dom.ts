/* A stand-in DOM for the functions that read the page (accessible names,
   declared verbs): elements with attributes, children, text, a parent, a
   document that finds by id, and the few properties of fields those
   functions read. Enough to test them without a browser. */

export interface StandInText {
  nodeType: 3
  nodeValue: string
  parentElement: StandInElement | null
}

export interface StandInElement {
  nodeType: 1
  tagName: string
  attributes: Record<string, string>
  childNodes: Array<StandInElement | StandInText>
  children: StandInElement[]
  parentElement: StandInElement | null
  ownerDocument: { getElementById: (id: string) => StandInElement | null }
  getAttribute: (name: string) => string | null
  readonly textContent: string
  value?: string
  checked?: boolean
  labels?: StandInElement[]
  selectedOptions?: StandInElement[]
}

type Child = StandInElement | string

/* The document every stand-in tree shares; `adopt` registers a root. */
const roots: StandInElement[] = []

function find(node: StandInElement, id: string): StandInElement | null {
  if (node.attributes.id === id) return node
  for (const child of node.children) {
    const hit = find(child, id)
    if (hit) return hit
  }
  return null
}

const document = {
  getElementById(id: string): StandInElement | null {
    for (const root of roots) {
      const hit = find(root, id)
      if (hit) return hit
    }
    return null
  },
}

/* One element: `h('button', { 'aria-label': 'Close' }, 'x')`. Properties
   of fields go in `props`. */
export function h(tag: string, attributes: Record<string, string> = {}, ...children: Child[]): StandInElement {
  return element(tag, attributes, {}, children)
}

export function element(tag: string, attributes: Record<string, string>, props: Partial<Pick<StandInElement, 'value' | 'checked' | 'labels' | 'selectedOptions'>>, children: Child[]): StandInElement {
  const el: StandInElement = {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    attributes,
    childNodes: [],
    children: [],
    parentElement: null,
    ownerDocument: document,
    getAttribute: (name) => (Object.prototype.hasOwnProperty.call(attributes, name) ? attributes[name] : null),
    get textContent(): string {
      return el.childNodes.map((n) => (n.nodeType === 3 ? n.nodeValue : n.textContent)).join('')
    },
    ...props,
  }
  for (const child of children) {
    if (typeof child === 'string') {
      el.childNodes.push({ nodeType: 3, nodeValue: child, parentElement: el })
    } else {
      child.parentElement = el
      el.childNodes.push(child)
      el.children.push(child)
    }
  }
  return el
}

/* Registers a tree so ids inside it resolve; returns it as an Element. */
export function adopt(root: StandInElement): Element {
  roots.push(root)
  return root as unknown as Element
}

export const asElement = (el: StandInElement): Element => el as unknown as Element
