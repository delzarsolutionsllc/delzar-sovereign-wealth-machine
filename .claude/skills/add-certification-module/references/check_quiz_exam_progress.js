const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1280, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
  const S = process.argv[2];
  await p.goto('http://localhost:8811/#quizzes'); await p.waitForSelector('.qcard');
  console.log('cards', await p.locator('.qcard').count());
  await p.screenshot({ path: S + '/s_quizzes.png' });
  await p.goto('http://localhost:8811/#obj-1.1'); await p.waitForSelector('h1'); await p.waitForTimeout(300);
  console.log('obj h1', await p.locator('h1').innerText(), 'quizzes', await p.locator('.qcard').count());
  await p.screenshot({ path: S + '/s_obj.png', fullPage: true });
  await p.click('a.qcard >> nth=0'); await p.waitForSelector('.choice');
  for (let k = 0; k < 30; k++) {
    if (await p.locator('h2:has-text("correct")').count()) break;
    if (await p.locator('.choice:not([disabled])').count() && await p.locator('button.choice').count()) { await p.keyboard.press('1'); }
    else if (await p.locator('button:has-text("Check my answer")').count()) {
      const box = p.locator('.choice input'); if (await box.count()) { await box.nth(0).check(); await box.nth(1).check(); }
      const sel = p.locator('.mrow select'); for (let j = 0; j < await sel.count(); j++) await sel.nth(j).selectOption({ index: 1 });
      const save = p.locator('button:has-text("Save this order")'); if (await save.count()) await save.click();
      await p.click('button:has-text("Check my answer")');
    }
    await p.waitForTimeout(100);
    const n = p.locator('button:has-text("Next question"), button:has-text("See my score")'); if (await n.count()) await n.first().click();
    await p.waitForTimeout(150);
  }
  console.log('quiz end:', await p.locator('#quizdone').innerText());
  await p.screenshot({ path: S + '/s_quizdone.png', fullPage: true });
  // exam
  await p.goto('http://localhost:8811/#exam'); await p.waitForSelector('#exam-kind'); await p.selectOption('#exam-kind', '1'); await p.selectOption('#exam-count', '15');
  await p.click('button:has-text("Start")'); await p.waitForSelector('.qgrid');
  const q1 = await p.locator('#qprompt').innerText();
  await p.keyboard.press('1'); await p.waitForTimeout(100);
  console.log('no auto-advance:', (await p.locator('#qprompt').innerText()) === q1, 'pressed', await p.locator('.choice[aria-pressed=true]').count());
  await p.keyboard.press('f'); await p.waitForTimeout(100);
  console.log('flag', await p.locator('button:has-text("Flagged for review")').count(), await p.locator('.qgrid button.flagged').count());
  await p.keyboard.press('n'); await p.waitForTimeout(100);
  await p.locator('.qgrid button').nth(4).click(); await p.waitForTimeout(100);
  console.log('grid jump label:', await p.locator('.q-head .label').innerText());
  await p.screenshot({ path: S + '/s_exam.png', fullPage: true });
  await p.click('button:has-text("Review & finish")'); await p.waitForSelector('#rv-h');
  console.log('review:', await p.locator('section.panel p').first().innerText());
  await p.screenshot({ path: S + '/s_review.png', fullPage: true });
  await p.click('button:has-text("Finish and score")'); await p.waitForSelector('#result-h');
  console.log('result:', await p.locator('#result-h').innerText(), 'focused', await p.evaluate(() => document.activeElement.id));
  // progress export/import
  await p.goto('http://localhost:8811/#progress'); await p.waitForSelector('#sync-h');
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('button:has-text("Export my progress")')]);
  const fp = S + '/exported.json'; await dl.saveAs(fp);
  const data = JSON.parse(require('fs').readFileSync(fp)); console.log('export quizzes', Object.keys(data.progress.quizzes), 'objectives', Object.keys(data.progress.objectives).length);
  const merged = await p.evaluate(d => { const canon = o => JSON.stringify(o, (k, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map(x => [x, v[x]])) : v);
    return canon(mergeProgress(d.progress, d.progress)) === canon(cleanProgress(d.progress)); }, data);   // same content, key order ignored
  console.log('merge idempotent', merged);
  await p.evaluate(() => localStorage.clear()); await p.reload(); await p.waitForSelector('#sync-h');
  await p.setInputFiles('#import-file', fp); await p.waitForTimeout(1800);
  console.log('after import rows', await p.locator('tbody tr').count());
  // tabs
  await p.goto('http://localhost:8811/#lab-1'); await p.waitForSelector('#tab-lesson'); await p.focus('#tab-lesson'); await p.keyboard.press('ArrowRight'); await p.waitForTimeout(400);
  console.log('tab focus', await p.evaluate(() => document.activeElement.id), await p.locator('#tab-scenario').getAttribute('aria-selected'));
  // phone
  await p.setViewportSize({ width: 390, height: 844 }); await p.goto('http://localhost:8811/#obj-2.4'); await p.waitForTimeout(500);
  console.log('overflow', await p.evaluate(() => document.documentElement.scrollWidth > innerWidth));
  await p.screenshot({ path: S + '/s_phone.png', fullPage: false });
  console.log('errors', errs);
  await b.close();
})();
