import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

/* Checks on the order of the library's own CSS rules: which rule wins
   where two set the same property on one element. */

const css = (path: string) => readFileSync(new URL(`../src/design-system/${path}`, import.meta.url), 'utf8')

/* The rules of a sheet as [selector, body], comments removed; nested
   at-rules are skipped. */
function rules(sheet: string): Array<[string, string]> {
  const text = sheet.replace(/\/\*[\s\S]*?\*\//g, '')
  const out: Array<[string, string]> = []
  const re = /([^{}@]+)\{([^{}]*)\}/g
  for (let m = re.exec(text); m; m = re.exec(text)) out.push([m[1].trim(), m[2]])
  return out
}

/* Specificity of one compound selector list item: [ids, classes and
   attributes and pseudo-classes, elements]. Enough for the library's
   plain selectors. */
function specificity(selector: string): [number, number, number] {
  const s = selector.replace(/::[a-z-]+/g, ' ').replace(/:(not|is|has)\(([^()]*)\)/g, ' $2')
  const ids = (s.match(/#[\w-]+/g) ?? []).length
  const classes = (s.match(/\.[\w-]+/g) ?? []).length + (s.match(/\[[^\]]+\]/g) ?? []).length + (s.match(/:[a-z-]+/g) ?? []).length
  const elements = (s.replace(/\[[^\]]+\]/g, '').match(/(^|[\s>+~])[a-z][\w-]*/g) ?? []).length
  return [ids, classes, elements]
}

const outranks = (a: [number, number, number], b: [number, number, number]) => a[0] > b[0] || (a[0] === b[0] && (a[1] > b[1] || (a[1] === b[1] && a[2] > b[2])))

/* The selectors (split on commas) of the rules whose body sets `property`
   and whose selector contains `part`. */
function settersOf(sheet: string, part: string, property: string): string[] {
  return rules(sheet)
    .filter(([, body]) => new RegExp(`(^|[;\\s])${property}\\s*:`).test(body))
    .flatMap(([selector]) => selector.split(',').map((x) => x.trim()))
    .filter((x) => x.includes(part))
}

describe('the waiting ring on a microsidebar item', () => {
  test('prints in the ground’s ink and outranks the status dot’s own ring', () => {
    const dot = settersOf(css('marks/StatusDot.css'), '[data-state="waiting"]', 'box-shadow')
    assert.equal(dot.length, 1)
    const micro = rules(css('frame/MicroSidebar.css')).filter(
      ([selector, body]) => selector.includes('.sl-micro-item-needs') && /box-shadow\s*:[^;]*var\(--sl-micro-ink\)/.test(body),
    )
    assert.equal(micro.length, 1)
    assert.ok(outranks(specificity(micro[0][0]), specificity(dot[0])), `${micro[0][0]} must outrank ${dot[0]}`)
  })
})

describe('a layer starts a new ink scope', () => {
  /* Every custom property the library sets from the window ground's ink,
     and that ink itself. */
  const SHEETS = ['frame/MicroSidebar.css', 'frame/AppFrame.css', 'frame/Sidebar.css', 'ground/WindowGround.css', 'frame/ActivityList.css']
  const groundInks = new Set(['--sl-ground-ink'])
  for (const sheet of SHEETS) {
    for (const [, body] of rules(css(sheet))) {
      for (const m of body.matchAll(/(--sl-[\w-]+)\s*:[^;]*var\(--sl-ground-ink\)/g)) groundInks.add(m[1])
    }
  }

  test('a popover (and so a menu) sets every ground ink back to the sheet’s', () => {
    assert.ok(groundInks.has('--sl-micro-ink'))
    const popover = rules(css('overlays/Popover.css')).find(([selector]) => selector === '.sl-popover')
    assert.ok(popover, 'the .sl-popover rule')
    for (const ink of groundInks) {
      assert.match(popover[1], new RegExp(`${ink}\\s*:\\s*var\\(--sl-(ink-[1-4]|hover|lit)\\)`), `${ink} is set back inside a layer`)
    }
  })
})

describe('RolePicker’s width', () => {
  test('it takes the width of its container, up to 560 px', () => {
    const picker = rules(css('frame/RolePicker.css')).find(([selector]) => selector === '.sl-role-picker')
    assert.ok(picker)
    assert.match(picker[1], /(^|;|\s)width:\s*100%;/)
    assert.match(picker[1], /max-width:\s*560px;/)
    assert.doesNotMatch(picker[1], /(^|;|\s)width:\s*560px/)
  })
})
