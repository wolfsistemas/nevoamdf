import { flattenProjectPieces, hardwareCounts } from './catalog.js'
import { sheetSpecs } from './store.js'
import { edgeMeters, pieceAreaM2 } from './nesting.js'

const qtyInt = (v) => Math.max(0, Math.floor(Number(v) || 0))

export function sheetAreaM2(settings) {
  return (Number(settings.sheetWidth || 0) * Number(settings.sheetHeight || 0)) / 1e6
}

export function panelPricePerM2(settings) {
  const area = sheetAreaM2(settings)
  return area > 0 ? Number(settings.sheetPrice || 0) / area : 0
}

function specPricePerM2(sp) {
  const w = Number(sp?.width) || 0
  const h = Number(sp?.height) || 0
  if (!(w > 0 && h > 0)) return 0
  return (Number(sp?.price) || 0) / ((w * h) / 1e6)
}

// Mapa espessura -> preço do m² da chapa cadastrada para aquela espessura.
// Quando há mais de uma chapa da mesma espessura, usa a de menor área
// (a mesma preferência do plano de corte). Chapas com preço 0 são ignoradas.
export function panelPriceMap(settings) {
  const map = new Map()
  for (const sp of sheetSpecs(settings)) {
    const w = Number(sp.width) || 0
    const h = Number(sp.height) || 0
    const price = Number(sp.price) || 0
    const thickness = Number(sp.thickness) || 0
    if (!(w > 0 && h > 0) || price <= 0) continue
    const area = w * h
    const cur = map.get(thickness)
    if (!cur || area < cur.area) {
      map.set(thickness, { perM2: price / (area / 1e6), area, price, name: sp.name, width: w, height: h })
    }
  }
  return map
}

export function panelPricePerM2For(settings, thickness) {
  const map = panelPriceMap(settings)
  const t = Number(thickness) || 0
  if (map.has(t)) return map.get(t).perM2
  // Espessura sem chapa cadastrada: usa a espessura mais próxima (empate p/ cima).
  let best = null
  for (const [k, v] of map) {
    const d = Math.abs(k - t)
    if (!best || d < best.d || (d === best.d && k > best.k)) best = { d, k, v }
  }
  return best ? best.v.perM2 : panelPricePerM2(settings)
}

export function itemMetrics(item) {
  const list = flattenProjectPieces({ furniture: [{ ...item, qty: 1 }] })
  let areaM2 = 0
  let tapeM = 0
  let pieceCount = 0
  const areaByThickness = new Map()
  for (const p of list) {
    const area = pieceAreaM2(p)
    areaM2 += area
    tapeM += edgeMeters(p)
    pieceCount += Math.max(0, Number(p.qty) || 0)
    const t = Number(p.thickness) || 0
    areaByThickness.set(t, (areaByThickness.get(t) || 0) + area)
  }
  return { areaM2, tapeM, pieceCount, areaByThickness }
}

function unitQty(item) {
  return Math.max(1, qtyInt(item.qty) || 1)
}

export function hardwareCost(item, settings) {
  const h = hardwareCounts(item)
  const handles = h.handles * Number(settings.handlePrice || 0)
  const hinges = h.hinges * Number(settings.hingePrice || 0)
  const slides = h.slides * Number(settings.slidePrice || 0)
  const tracks = h.tracks * Number(settings.trackPrice || 0)
  const feet = h.feetBuy * Number(settings.footPrice || 0)
  const locks = (h.locks || 0) * Number(settings.lockPrice || 0)
  const rods = (h.rods || 0) * Number(settings.rodPrice || 0)
  return {
    ...h,
    handlesCost: handles,
    hingesCost: hinges,
    slidesCost: slides,
    tracksCost: tracks,
    feetCost: feet,
    locksCost: locks,
    rodsCost: rods,
    hardware: handles + hinges + slides + tracks + feet + locks + rods
  }
}

export function itemCost(item, settings) {
  const { areaByThickness, ...m } = itemMetrics(item)
  let panel = 0
  const panelByThickness = []
  for (const [thickness, area] of areaByThickness) {
    const perM2 = panelPricePerM2For(settings, thickness)
    const value = area * perM2
    panel += value
    panelByThickness.push({ thickness, areaM2: area, perM2, value })
  }
  panelByThickness.sort((a, b) => a.thickness - b.thickness)
  const tape = m.tapeM * Number(settings.tapePricePerMeter || 0)
  const material = panel + tape
  const laborPct = Number(settings.laborPercent || 0)
  const labor = material * (laborPct / 100)
  const hw = hardwareCost(item, settings)
  return { ...m, ...hw, panelByThickness, panel, tape, material, labor, cost: material + labor + hw.hardware }
}

export function rateioCtx(furniture, settings, sheets, basis, layout) {
  let totalPanelLine = 0
  for (const f of furniture || []) {
    totalPanelLine += itemCost(f, settings).panel * unitQty(f)
  }
  const sheetCount = Math.max(0, Math.floor(Number(sheets) || 0))
  const boards = (layout && layout.boards) || []
  const sheetCost = boards.length
    ? boards.reduce((s, b) => s + Number(b.sheetPrice || 0), 0)
    : sheetCount * Number(settings.sheetPrice || 0)
  const wasteCost = Math.max(0, sheetCost - totalPanelLine)
  return {
    basis: basis === 'rateio' ? 'rateio' : 'used',
    totalPanelLine,
    sheetCost,
    wasteCost
  }
}

function adjustPanel(c, qty, ctx) {
  if (!ctx || ctx.basis !== 'rateio') return c.panel
  if (!(ctx.totalPanelLine > 0) || !(ctx.wasteCost > 0)) return c.panel
  const linePanel = c.panel * qty
  return c.panel + ctx.wasteCost * (linePanel / ctx.totalPanelLine) / qty
}

export function saleCalc(item, settings, ctx) {
  const c = itemCost(item, settings)
  const hasOverride = item.margin !== undefined && item.margin !== null
  const margin = hasOverride ? Number(item.margin) : Number(settings.defaultMargin || 0)
  const qty = unitQty(item)
  const panel = adjustPanel(c, qty, ctx)
  const material = panel + c.tape
  const laborPct = Number(settings.laborPercent || 0)
  const labor = material * (laborPct / 100)
  const hardware = Number(c.hardware || 0)
  const cost = material + labor + hardware
  const salePerUnit = cost * (1 + margin / 100)
  return { ...c, panel, material, labor, hardware, cost, margin, hasOverride, qty, salePerUnit, lineTotal: salePerUnit * qty, costLine: cost * qty }
}

export function projectTotals(furniture, settings, ctx) {
  let cost = 0
  let sale = 0
  let profit = 0
  let count = 0
  let units = 0
  for (const f of furniture || []) {
    const s = saleCalc(f, settings, ctx)
    cost += s.costLine
    sale += s.lineTotal
    profit += s.lineTotal - s.costLine
    count += 1
    units += s.qty
  }
  return { cost, sale, profit, count, units }
}
