import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { isTopLayer, layerOpenFrom, onLayersChange, pushLayer, removeLayer } from '../src/design-system/lib/layer'

/* A stand-in for a DOM subtree: `contains` answers for the nodes listed. */
function subtree(...nodes: object[]): Pick<Node, 'contains'> {
  return { contains: (node: Node | null) => node !== null && nodes.includes(node) }
}

describe('the layer stack', () => {
  test('a layer opened from inside a container is found until it closes', () => {
    const trigger = {} as Node
    const elsewhere = {} as Node
    const peek = subtree(trigger)
    assert.equal(layerOpenFrom(peek), false)
    const outside = pushLayer(elsewhere)
    assert.equal(layerOpenFrom(peek), false)
    const menu = pushLayer(trigger)
    assert.equal(layerOpenFrom(peek), true)
    removeLayer(menu)
    assert.equal(layerOpenFrom(peek), false)
    removeLayer(outside)
  })

  test('a layer with no origin belongs to no container', () => {
    const token = pushLayer()
    assert.equal(layerOpenFrom(subtree({})), false)
    assert.equal(layerOpenFrom(null), false)
    removeLayer(token)
  })

  test('the newest layer is on top; removing it hands the top back', () => {
    const a = pushLayer()
    const b = pushLayer()
    assert.equal(isTopLayer(b), true)
    assert.equal(isTopLayer(a), false)
    removeLayer(b)
    assert.equal(isTopLayer(a), true)
    removeLayer(a)
  })

  test('listeners hear every open and close, once each, until they stop', () => {
    let heard = 0
    const stop = onLayersChange(() => heard++)
    const token = pushLayer()
    removeLayer(token)
    removeLayer(token)
    assert.equal(heard, 2)
    stop()
    removeLayer(pushLayer())
    assert.equal(heard, 2)
  })
})
