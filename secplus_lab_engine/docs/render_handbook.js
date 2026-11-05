const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file://' + process.argv[2], { waitUntil: 'load' });
  await page.pdf({
    path: process.argv[3], format: 'Letter', printBackground: true, preferCSSPageSize: true,
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: '<div style="font-size:7.5pt;color:#59636e;width:100%;padding:0 0.7in;display:flex;justify-content:space-between;font-family:Helvetica,Arial,sans-serif"><span>Delzar Certification Academy — Technical Handbook</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
  });
  await browser.close();
})();
