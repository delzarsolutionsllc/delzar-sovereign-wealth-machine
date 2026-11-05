const { chromium } = require('playwright'); const fs = require('fs');
const S = process.argv[2]; const AXE = fs.readFileSync(S + '/axe/node_modules/axe-core/axe.min.js', 'utf8');
(async () => {
  const b = await chromium.launch(); const all = {};
  for (const scheme of ['light', 'dark']) {
    const p = await b.newPage({ viewport: { width: 1280, height: 900 }, colorScheme: scheme });
    const run = async (label) => {
      await p.addScriptTag({ content: AXE });
      const r = await p.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] } })).violations
        .map(v => ({ id: v.id, impact: v.impact, help: v.help, n: v.nodes.length, ex: v.nodes.slice(0, 3).map(n => n.target.join(' ') + ' :: ' + (n.failureSummary || '').split('\n').slice(1, 2).join(' ')) })));
      for (const v of r) { const k = v.id; (all[k] ||= { impact: v.impact, help: v.help, where: [] }).where.push(`${scheme}:${label} (${v.n}) ${v.ex.join(' | ')}`); }
    };
    const go = async (h, sel = 'h1') => { await p.goto('http://localhost:8811/' + h); await p.waitForSelector(sel); await p.waitForTimeout(400); };
    for (const h of ['#home', '#review', '#videos', '#quizzes', '#obj-2.4', '#progress', '#career', '#exam', '#lab-1']) { await go(h); await run(h); }
    await p.click('#tab-practice'); await p.waitForTimeout(200); await p.click('button:has-text("Practise on the sample scenario")'); await p.waitForSelector('.choice'); await run('lab-practice');
    await p.keyboard.press('1'); await p.waitForTimeout(200); await run('lab-practice-answered');
    await p.click('#tab-case'); await p.waitForSelector('.casestudy'); await run('case');
    await go('#quiz-2.4-t1', '.choice'); await run('quiz'); await p.keyboard.press('1'); await p.waitForTimeout(200); await run('quiz-answered');
    await go('#exam'); await p.click('button:has-text("Start")'); await p.waitForSelector('#qprompt'); await run('exam');
    await p.click('button:has-text("Review & finish")'); await p.waitForSelector('#rv-h'); await run('exam-review');
    await p.click('button:has-text("Finish and score")'); await p.waitForSelector('#result-h'); await run('exam-result');
    await go('#review'); await p.click('#review-start'); await p.waitForSelector('.choice'); await run('daily-review');
    await p.setViewportSize({ width: 390, height: 844 }); await go('#home'); await run('phone-home'); await p.click('#maptoggle'); await run('phone-map');
    await p.close();
  }
  for (const [k, v] of Object.entries(all)) { console.log(`\n[${v.impact}] ${k}: ${v.help} — ${v.where.length} page(s)`); v.where.slice(0, 4).forEach(w => console.log('   ' + w.slice(0, 300))); }
  console.log('\nTOTAL rule violations:', Object.keys(all).length);
  await b.close();
})();
