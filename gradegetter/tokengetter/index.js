const puppeteer = require('puppeteer');
const { PuppeteerScreenRecorder } = require('puppeteer-screen-recorder');

(async () => {
  try {
    const args = process.argv;
    const browser = await puppeteer.launch({
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
      headless: 'new',
      args: [
        '--disable-setuid-sandbox',
        '--disable-gpu',
        //        '--disable-dev-shm-usage',
        '--no-sandbox',
        '--disable-blink-features=AutomationControlled',
        '--window-size=1280,720',
        '--single-process',
        '--no-zygote']
    });

    const page = await browser.newPage();

    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => false });
    });

    await page.setUserAgent('Mozilla/6.0 (X11; Linux x86_64) AppleWebKit/538.40 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36');

    const recorder = new PuppeteerScreenRecorder(page);
    await recorder.start("/app/recordings/recording.mp4");
    console.error("Started,1"); // Started

    // login
    await page.goto('https://essexnorthshore.schoology.com/');
    console.error("Navigated to Schoology login,2"); // Went to schoology page

    await page.waitForSelector('input[type="email"]', {
      visible: true,
      timeout: 30000
    });
    await page.type('input[type="email"]', `${args[2]}`); // <-- config value
    console.error("Typed in Email,3"); // Typed email
    await page.click('#identifierNext');
    console.error("Entered Email,4"); // entered email


    await page.waitForSelector('input[type="password"]', {
      visible: true,
      timeout: 30000
    });
    await page.type('input[type="password"]', `${args[3]}`); // <-- config value
    console.error("Typed in Password,5"); // typed password
    await page.click('#passwordNext');
    console.error("Enter Password,6"); // entered password
    await page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 30000 });

    // Cookie time
    let cookies = await browser.cookies()

    const sessCookie = cookies.find(cookies =>
      cookies.name.startsWith("SESS") &&
      cookies.domain === ".essexnorthshore.schoology.com"
    );

    if (!sessCookie) {
      console.error("ERROR: no session cookie found; login may have failed");
      process.exit(1);
    }

    let cookie = `${sessCookie.name}=${sessCookie.value}`;
    console.error("Finished,7"); // grabbed cookie
    console.log(cookie);

    await browser.close();
    await recorder.stop();

  } catch (error) {
    console.error(`ERROR: ${error.message}`);
    await recorder.stop();
    process.exit(1);
  }
})();
