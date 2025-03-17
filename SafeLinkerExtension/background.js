// List of homoglyph characters
const HOMOGRAPHS = {
  'a': ['а', 'ä', 'ạ', 'α'],
  'b': ['Ь', 'ḅ', 'ƅ'],
  'e': ['е', 'ë', 'ẹ', 'ɛ'],
  'i': ['і', 'í', 'ï', 'ị'],
  'l': ['ӏ', 'ł', 'ḷ'],
  'o': ['о', 'ö', 'ọ', '○'],
  's': ['ѕ', 'ṡ', 'ṣ']
};

// Function to convert to Punycode
function toPunycode(domain) {
  try {
    return domain.toLowerCase().startsWith('xn--') ? domain : new URL(`http://${domain}`).hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

// Check for homoglyphs
function checkHomographs(domain) {
  const suspicious = [];
  for (let char of domain.toLowerCase()) {
    for (let key in HOMOGRAPHS) {
      if (HOMOGRAPHS[key].includes(char)) {
        suspicious.push([char, key]);
      }
    }
  }
  return suspicious;
}

// Detect suspicious domain
function isSuspicious(domain) {
  const punycode = toPunycode(domain);
  const homographs = checkHomographs(domain);
  return homographs.length > 0 || (punycode && punycode.startsWith('xn--'));
}

// Send message to content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "checkLink") {
    const suspicious = isSuspicious(message.domain);
    sendResponse({ suspicious });
  }
});