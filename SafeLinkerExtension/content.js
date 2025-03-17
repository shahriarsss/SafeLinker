// Check all links on the page
function checkLinks() {
  const links = document.getElementsByTagName('a');
  for (let link of links) {
    const href = link.getAttribute('href');
    if (href) {
      chrome.runtime.sendMessage({ type: "checkLink", domain: href }, (response) => {
        if (response.suspicious) {
          link.style.color = "red"; // Mark suspicious link
          link.addEventListener('click', (e) => {
            e.preventDefault(); // Block the click
            alert(`Warning: The domain "${href}" might be fake!`);
          });
        }
      });
    }
  }
}

// Run the function when the page loads
window.addEventListener('load', checkLinks);
// Check for dynamic changes on the page
const observer = new MutationObserver(checkLinks);
observer.observe(document.body, { childList: true, subtree: true });