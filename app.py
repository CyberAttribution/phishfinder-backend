// popup.js - Rewritten for Structured JSON Streaming

document.addEventListener('DOMContentLoaded', function () {
  // --- CONFIGURATION ---
  const API_BASE_URL = 'https://phishfinder-backend.onrender.com';

  // --- ELEMENT REFERENCES ---
  const standardCheckButton = document.getElementById('standardCheckButton');
  const deepCheckButton = document.getElementById('deepCheckButton');
  const phishInput = document.getElementById('phishInput');
  const resultContainer = document.getElementById('result');
  const subscribeButton = document.getElementById('subscribeButton');
  const copyButton = document.getElementById('copyButton');
  const copyAlertButton = document.getElementById('copyAlertButton');
  const copySocialButton = document.getElementById('copySocialButton');


  // --- STATE VARIABLES ---
  let isAnalyzing = false;
  let analysisController = null;

  // --- EVENT LISTENERS ---
  standardCheckButton.addEventListener('click', () => streamAnalysis());
  deepCheckButton.addEventListener('click', () => streamAnalysis());
  
  if (subscribeButton) subscribeButton.addEventListener('click', handleSubscription);
  if (copyButton) copyButton.addEventListener('click', copyMainResults);
  if (copyAlertButton) copyAlertButton.addEventListener('click', () => copyTextFromElement('securityAlert', 'copyAlertButton'));
  if (copySocialButton) copySocialButton.addEventListener('click', () => copyTextFromElement('socialPost', 'copySocialButton'));

  // --- PRIMARY STREAMING WORKFLOW ---
  async function streamAnalysis() {
    if (isAnalyzing) return;
    
    const inputValue = phishInput.value.trim();
    if (!inputValue) {
      alert('Please enter a value to analyze.');
      return;
    }

    setLoadingState(true);
    // Restore the detailed HTML structure for the results
    restoreResultStructure(); 
    
    analysisController = new AbortController();

    try {
      const response = await fetch(`${API_BASE_URL}/api/stream-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: inputValue }),
        signal: analysisController.signal,
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }
      
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = '';

      // Read from the stream
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        
        buffer += value;

        // Process all complete JSON objects in the buffer (separated by newlines)
        let boundary;
        while ((boundary = buffer.indexOf('\n')) >= 0) {
          const jsonString = buffer.substring(0, boundary);
          buffer = buffer.substring(boundary + 1);
          
          if (jsonString.trim() === '') continue;

          try {
            const chunk = JSON.parse(jsonString);
            updateUIWithChunk(chunk);
          } catch (error) {
            console.error('Failed to parse JSON chunk:', jsonString, error);
          }
        }
      }

    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Streaming analysis error:', error);
        showErrorState(`A critical error occurred: ${error.message}`);
      }
    } finally {
      setLoadingState(false);
    }
  }

  // --- UI HELPER FUNCTIONS ---

  function restoreResultStructure() {
    resultContainer.innerHTML = `
      <p><strong>Phishing Risk:</strong> <span id="risk">Analyzing...</span></p>
      <p><strong>Summary:</strong> <span id="summary"></span></p>
      <p><strong>Domain Created:</strong> <span id="domainAge"></span></p> 
      <p><strong>MX Records Found:</strong> <span id="mxRecords"></span></p>
      <p><strong>What to Watch For:</strong></p>
      <ul id="watchFor"></ul>
      <p><strong>Advice:</strong> <span id="advice"></span></p>
    `;
    // Clear the generated content textareas as well
    const actionableContentDiv = document.getElementById('actionable-content');
    if (actionableContentDiv) {
        actionableContentDiv.style.display = 'none';
        document.getElementById('securityAlert').value = '';
        document.getElementById('socialPost').value = '';
    }
  }

  function updateUIWithChunk(chunk) {
    if (!chunk || !chunk.type || chunk.content === undefined) return;

    // Hide the initial "Analyzing..." text for risk once we get the real value
    if (chunk.type === 'risk' && document.getElementById('risk').textContent === 'Analyzing...') {
        document.getElementById('risk').textContent = '';
    }

    switch (chunk.type) {
      case 'risk':
        const riskSpan = document.getElementById('risk');
        riskSpan.textContent = `${chunk.content.level} (${chunk.content.score}/100)`;
        riskSpan.className = chunk.content.class.toLowerCase();
        break;
      case 'summary':
        document.getElementById('summary').textContent = chunk.content;
        break;
      case 'domainAge':
        document.getElementById('domainAge').textContent = chunk.content;
        break;
      case 'mxRecords':
        document.getElementById('mxRecords').textContent = chunk.content;
        break;
      case 'watchFor':
        const watchForList = document.getElementById('watchFor');
        const li = document.createElement('li');
        li.textContent = chunk.content;
        watchForList.appendChild(li);
        break;
      case 'advice':
        document.getElementById('advice').textContent = chunk.content;
        break;
      case 'generated': // For actionable content
         const actionableContentDiv = document.getElementById('actionable-content');
         if (actionableContentDiv) {
            actionableContentDiv.style.display = 'block';
            document.getElementById('securityAlert').value = chunk.content.securityAlert;
            document.getElementById('socialPost').value = chunk.content.socialPost;
         }
         break;
      case 'error':
        showErrorState(chunk.content);
        break;
    }
  }

  function setLoadingState(isLoading) {
    isAnalyzing = isLoading;
    standardCheckButton.disabled = isLoading;
    deepCheckButton.disabled = isLoading;

    if (isLoading) {
      standardCheckButton.textContent = 'Analyzing...';
      deepCheckButton.textContent = 'Analyzing...';
    } else {
      standardCheckButton.textContent = 'Standard Analysis';
      deepCheckButton.textContent = 'Deep Analysis';
      // Show copy and VirusTotal buttons after analysis
      if(document.getElementById('copyButton')) document.getElementById('copyButton').style.display = 'inline-block';
      const virusTotalLink = document.getElementById('virusTotalLink');
      if(virusTotalLink) {
          virusTotalLink.style.display = 'inline-block';
          virusTotalLink.href = `https://www.virustotal.com/gui/search/${encodeURIComponent(phishInput.value)}`;
      }
    }
  }

  function showErrorState(message) {
    setLoadingState(false);
    resultContainer.innerHTML = `
      <p><strong>Phishing Risk:</strong> <span id="risk" class="red">Error</span></p>
      <p><strong>Summary:</strong> <span id="summary">${message}</span></p>
    `;
  }
  
  // --- OTHER HELPER FUNCTIONS (UNCHANGED) ---
  
  function handleSubscription() {
    const emailInput = document.getElementById('emailInput');
    const email = emailInput.value.trim();
    if (email) {
      const subButton = document.getElementById('subscribeButton');
      subButton.textContent = "Subscribing...";
      subButton.disabled = true;
      fetch(`${API_BASE_URL}/api/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      })
      .then(res => res.json())
      .then(subData => {
        subButton.textContent = "Subscribed!";
        setTimeout(() => { subButton.textContent = "Subscribe"; subButton.disabled = false; emailInput.value = ''; }, 2000);
      })
      .catch(err => {
        console.error("Subscription fetch error:", err);
        subButton.textContent = "Error";
        setTimeout(() => { subButton.textContent = "Subscribe"; subButton.disabled = false; }, 2000);
      });
    }
  }
  
  function copyMainResults() {
      const risk = document.getElementById('risk').textContent;
      const summary = document.getElementById('summary').textContent;
      const domainAge = document.getElementById('domainAge').textContent;
      const mxRecords = document.getElementById('mxRecords').textContent;
      const advice = document.getElementById('advice').textContent;
      const indicatorsList = document.getElementById('watchFor').getElementsByTagName('li');
      let indicatorsText = "";
      for (let i = 0; i < indicatorsList.length; i++) {
          indicatorsText += `- ${indicatorsList[i].textContent}\n`;
      }
      const formattedText = `PhishFinder Analysis\n--------------------\nRisk: ${risk}\nDomain Created: ${domainAge}\nMX Records: ${mxRecords}\n\nSummary:\n${summary}\n\nWhat to Watch For:\n${indicatorsText}\nAdvice:\n${advice}`;
      navigator.clipboard.writeText(formattedText).then(() => {
          updateCopyButtonState('copyButton');
      }).catch(err => {
          console.error('Failed to copy results: ', err);
      });
  }

  function copyTextFromElement(elementId, buttonId) {
    const textToCopy = document.getElementById(elementId).value;
    navigator.clipboard.writeText(textToCopy).then(() => {
        updateCopyButtonState(buttonId);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
  }

  function updateCopyButtonState(buttonId) {
    const button = document.getElementById(buttonId);
    if (!button) return;
    const originalText = button.textContent;
    button.textContent = "Copied!";
    button.disabled = true;
    setTimeout(() => {
        button.textContent = originalText;
        button.disabled = false;
    }, 2000);
  }
});
